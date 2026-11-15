// =====================================================================
//  DevSecOps pipeline - Healthcare Appointment API (container port 8000)
//
//  Assumptions:
//   * Jenkins runs directly on the host (NOT inside a container) with
//     docker + kubectl on PATH; the 'jenkins' user is in the docker group.
//   * Jenkins credentials:
//        dockerhub  -> Username with password (Docker Hub user + access token)
//        kubeconfig -> Secret file (see scripts/make-jenkins-kubeconfig.sh)
//   * Change DOCKERHUB_USER below.
// =====================================================================

// Run a block with KUBECONFIG pointing at the Jenkins kubeconfig credential
def withKube(Closure body) {
    withCredentials([file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')]) {
        body()
    }
}

// Apply manifests to a namespace with the freshly built image; roll back on failure
def deployTo(String ns) {
    try {
        sh """
            kubectl -n ${ns} apply -f k8s/app/pvc.yaml -f k8s/app/service.yaml
            sed "s|your-dockerhub-username/health-api:0.0.0|\$IMAGE|" k8s/app/deployment.yaml | kubectl -n ${ns} apply -f -
            kubectl -n ${ns} rollout status deployment/health-api --timeout=180s
        """
    } catch (err) {
        sh "kubectl -n ${ns} rollout undo deployment/health-api || true"
        throw err
    }
}

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    parameters {
        booleanParam(name: 'RUN_SONAR', defaultValue: false,
                     description: 'Run SonarQube SAST (needs a SonarQube server + Jenkins plugin, server name "sonar")')
    }

    environment {
        DOCKERHUB_USER = 'pranav4dit'          // <-- CHANGE THIS
        IMAGE          = "${DOCKERHUB_USER}/health-api:${BUILD_NUMBER}"
        TEST_PORT      = '8000'   // local port used by port-forward during DAST (Jenkins itself uses 8080)
    }

    stages {

        stage('Checkout') {
            steps { checkout scm }
        }

        // 1. Secrets must never reach Git history
        stage('Secret Scan - Gitleaks') {
            steps {
                sh '''
                    docker run --rm -v "$PWD:/repo" --entrypoint sh zricethezav/gitleaks:latest -c \
                      "git config --global --add safe.directory /repo && gitleaks detect --source /repo --exit-code 1 --redact --no-banner"
                '''
            }
        }

        stage('Unit Tests') {
            steps {
                sh 'bash scripts/pyrun.sh "pip install --user -q -r src/requirements.txt -r requirements-dev.txt && python -m pytest -q -p no:cacheprovider --junitxml=test-results.xml"'
            }
            post { always { junit allowEmptyResults: true, testResults: 'test-results.xml' } }
        }

        // 2. SAST - look for insecure code patterns without running the app
        stage('SAST - Bandit') {
            steps {
                sh 'bash scripts/pyrun.sh "pip install --user -q bandit && python -m bandit -r src -ll"'
            }
        }

        stage('SAST - SonarQube') {
            when { expression { params.RUN_SONAR } }
            steps {
                withSonarQubeEnv('sonar') {
                    sh '''
                        docker run --rm --network host -u "$(id -u):$(id -g)" \
                          -e SONAR_HOST_URL="$SONAR_HOST_URL" -e SONAR_TOKEN="$SONAR_AUTH_TOKEN" \
                          -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli
                    '''
                }
                timeout(time: 5, unit: 'MINUTES') { waitForQualityGate abortPipeline: true }
            }
        }

        // 3. SCA - known CVEs in third-party libraries
        stage('SCA - pip-audit') {
            steps {
                sh 'bash scripts/pyrun.sh "pip install --user -q pip-audit && python -m pip_audit -r src/requirements.txt"'
            }
        }

        // 4. IaC scan - Dockerfile + Kubernetes manifests
        //    Skipped checks (documented in README): CKV_K8S_43 image digest,
        //    CKV_K8S_35 secrets via env (we use secretRef), CKV_K8S_21 namespace chosen at deploy time (-n)
        stage('Config Scan - Checkov') {
            steps {
                sh '''
                    docker run --rm -v "$PWD:/src" bridgecrew/checkov:latest -d /src \
                      --framework dockerfile kubernetes \
                      --skip-check CKV_K8S_43,CKV_K8S_35,CKV_K8S_21 \
                      --quiet --compact
                '''
            }
        }

        stage('Build Image') {
            steps { sh 'docker build -t "$IMAGE" .' }
        }

        // 5. Container scan - fail on fixable HIGH/CRITICAL vulnerabilities
        stage('Image Scan - Trivy') {
            steps {
                sh '''
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      -v trivy-cache:/root/.cache/ \
                      aquasec/trivy:latest image \
                      --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed --no-progress "$IMAGE"
                '''
            }
        }

        stage('Push Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub',
                                                  usernameVariable: 'DH_USER', passwordVariable: 'DH_PASS')]) {
                    sh '''
                        echo "$DH_PASS" | docker login -u "$DH_USER" --password-stdin
                        docker push "$IMAGE"
                        docker logout
                    '''
                }
            }
        }

        stage('Deploy to TEST') {
            steps { script { withKube { deployTo('health-test') } } }
        }

        // 6. DAST - attack the RUNNING app in the test namespace
        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    withKube {
                        sh '''
                            mkdir -p zap-out && chmod 777 zap-out
                            kubectl -n health-test port-forward svc/health-api ${TEST_PORT}:80 > pf.log 2>&1 &
                            echo $! > pf.pid
                            for i in $(seq 1 15); do curl -fs http://localhost:${TEST_PORT}/health >/dev/null && break; sleep 2; done

                            set +e
                            docker run --rm --network host -v "$PWD/zap-out:/zap/wrk:rw" \
                              ghcr.io/zaproxy/zaproxy:stable \
                              zap-baseline.py -t http://localhost:${TEST_PORT} -r zap-report.html
                            rc=$?
                            set -e

                            kill $(cat pf.pid) 2>/dev/null || true
                            # ZAP exit codes: 0 pass, 1 FAIL alerts, 2 warnings only, 3+ error
                            if [ "$rc" -eq 1 ] || [ "$rc" -ge 3 ]; then exit "$rc"; fi
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-out/*.html', allowEmptyArchive: true
                    sh 'if [ -f pf.pid ]; then kill $(cat pf.pid) 2>/dev/null || true; fi'
                }
            }
        }

        // 7. Production only from main, and only after a human approves
        stage('Approve & Deploy to PROD') {
            when { expression { env.GIT_BRANCH ==~ /(origin\/)?main/ } }
            steps {
                timeout(time: 30, unit: 'MINUTES') {
                    input message: "All security gates passed for ${env.IMAGE}. Deploy to PRODUCTION?", ok: 'Deploy'
                }
                script { withKube { deployTo('health-prod') } }
            }
        }
    }

    post {
        success { echo "Pipeline passed all security gates. Image: ${env.IMAGE}" }
        failure { echo 'Pipeline BLOCKED by a security gate or build error. Nothing reached production.' }
    }
}
