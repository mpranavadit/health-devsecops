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
    agent {
        label 'windows-docker'
    }

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        DOCKERHUB_USER = 'pranav4dit'
        IMAGE = "pranav4dit/health-api:${BUILD_NUMBER}"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Secret Scan - Gitleaks') {
            steps {
                bat '''
                docker run --rm -v "%WORKSPACE%:/repo" ^
                  --entrypoint gitleaks zricethezav/gitleaks:latest ^
                  git /repo --redact
                '''
            }
        }

        stage('Unit Tests') {
            steps {
                bat '''
                python -m pip install -r src/requirements.txt -r requirements-dev.txt
                python -m pytest -q -p no:cacheprovider --junitxml=test-results.xml
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'test-results.xml'
                }
            }
        }

        stage('SAST - Bandit') {
            steps {
                bat '''
                python -m pip install bandit
                python -m bandit -r src -ll
                '''
            }
        }

        stage('SCA - pip-audit') {
            steps {
                bat '''
                python -m pip install pip-audit
                python -m pip_audit -r src/requirements.txt
                '''
            }
        }

        stage('Config Scan - Checkov') {
            steps {
                bat '''
                docker run --rm -v "%WORKSPACE%:/src" bridgecrew/checkov:latest ^
                  -d /src --framework dockerfile kubernetes --quiet --compact
                '''
            }
        }

        stage('Build Image') {
            steps {
                bat 'docker build -t %IMAGE% .'
            }
        }

        stage('Image Scan - Trivy') {
            steps {
                bat '''
                docker save -o health-api.tar %IMAGE%
                docker run --rm -v "%WORKSPACE%:/work" aquasec/trivy:latest ^
                  image --input /work/health-api.tar ^
                  --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed
                '''
            }
        }

        stage('Push Image') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'dockerhub',
                        usernameVariable: 'DH_USER',
                        passwordVariable: 'DH_PASS'
                    )
                ]) {
                    bat '''
                    echo %DH_PASS%| docker login -u %DH_USER% --password-stdin
                    docker push %IMAGE%
                    docker logout
                    '''
                }
            }
        }

        stage('Deploy to TEST') {
            steps {
                withCredentials([
                    file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')
                ]) {
                    powershell '''
                    kubectl apply -f k8s/app/pvc.yaml -n health-test
                    kubectl apply -f k8s/app/service.yaml -n health-test

                    $manifest = Get-Content k8s/app/deployment.yaml -Raw
                    $manifest = $manifest.Replace("health-api:local", $env:IMAGE)
                    $manifest = $manifest.Replace("your-dockerhub-username/health-api:0.0.0", $env:IMAGE)
                    $manifest = $manifest -replace "imagePullPolicy: IfNotPresent", "imagePullPolicy: Always"

                    $manifest | Set-Content deployment-ci.yaml
                    kubectl apply -f deployment-ci.yaml -n health-test
                    kubectl rollout status deployment/health-api -n health-test --timeout=180s

                    if ($LASTEXITCODE -ne 0) { throw "TEST deployment failed" }
                    '''
                }
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                powershell '''
                New-Item -ItemType Directory -Force zap-out | Out-Null

                $pf = Start-Process kubectl `
                    -ArgumentList "port-forward -n health-test svc/health-api 8000:80" `
                    -PassThru -WindowStyle Hidden

                try {
                    Start-Sleep -Seconds 5

                    docker run --rm -v "${env:WORKSPACE}\\zap-out:/zap/wrk" `
                        ghcr.io/zaproxy/zaproxy:stable `
                        zap-baseline.py -t http://host.docker.internal:8000 `
                        -r zap-report.html

                    if ($LASTEXITCODE -eq 1 -or $LASTEXITCODE -ge 3) {
                        throw "OWASP ZAP security scan failed"
                    }
                }
                finally {
                    Stop-Process -Id $pf.Id -Force -ErrorAction SilentlyContinue
                }
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-out/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('Approve and Deploy PROD') {
            steps {
                input message: 'Approve production deployment?', ok: 'Deploy'

                withCredentials([
                    file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')
                ]) {
                    powershell '''
                    kubectl apply -f k8s/app/pvc.yaml -n health-prod
                    kubectl apply -f k8s/app/service.yaml -n health-prod

                    $manifest = Get-Content k8s/app/deployment.yaml -Raw
                    $manifest = $manifest.Replace("health-api:local", $env:IMAGE)
                    $manifest = $manifest.Replace("your-dockerhub-username/health-api:0.0.0", $env:IMAGE)
                    $manifest = $manifest -replace "imagePullPolicy: IfNotPresent", "imagePullPolicy: Always"

                    $manifest | Set-Content deployment-prod.yaml
                    kubectl apply -f deployment-prod.yaml -n health-prod
                    kubectl rollout status deployment/health-api -n health-prod --timeout=180s

                    if ($LASTEXITCODE -ne 0) { throw "PROD deployment failed" }
                    '''
                }
            }
        }
    }

    post {
        success {
            echo 'Healthcare DevSecOps pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed. Check the stage logs.'
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
