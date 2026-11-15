
pipeline {
    agent {
        label 'windows-docker'
    }

    options {
        timestamps()
        timeout(time: 90, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
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
                python -m pip uninstall -y jwt
                python -m pip install -r src/requirements.txt -r requirements-dev.txt
                python -c "import jwt; assert hasattr(jwt, 'encode')"
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
                python -m pip uninstall -y bandit
                python -m pip install --no-cache-dir bandit==1.9.4
                python -m bandit -r src -ll
                '''
            }
        }

        stage('SCA - pip-audit') {
            steps {
                bat '''
                python -m pip install pip-audit
                python -m pip_audit -r src/requirements.txt --timeout 60 --progress-spinner off
                '''
            }
        }

        stage('Config Scan - Dockerfile') {
            steps {
                bat '''
                docker run --rm -v "%WORKSPACE%:/src" bridgecrew/checkov:latest ^
                  -d /src --framework dockerfile --quiet --compact
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
                  --scanners vuln ^
                  --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed
                '''
            }
        }

        stage('Load Image into Minikube') {
            steps {
                powershell '''
                $ErrorActionPreference = "Stop"

                Write-Host "Checking Minikube status..."

                minikube status
                if ($LASTEXITCODE -ne 0) {
                    throw "Minikube is unavailable"
                }

                Write-Host "Loading application image into Minikube..."

                minikube image load $env:IMAGE
                if ($LASTEXITCODE -ne 0) {
                    throw "Failed to load image into Minikube"
                }

                Write-Host "Verifying image..."

                minikube image ls | Select-String "health-api"

                if ($LASTEXITCODE -ne 0) {
                    throw "Image verification failed"
                }
                '''
            }
        }

        stage('Prepare Kubernetes Manifest') {
            steps {
                powershell '''
                $ErrorActionPreference = "Stop"

                $manifest = Get-Content k8s/app/deployment.yaml -Raw

                $manifest = $manifest.Replace(
                    "health-api:local",
                    $env:IMAGE
                )

                $manifest = $manifest.Replace(
                    "imagePullPolicy: Always",
                    "imagePullPolicy: IfNotPresent"
                )

                if ($manifest -notmatch [regex]::Escape($env:IMAGE)) {
                    throw "Image replacement failed"
                }

                New-Item -ItemType Directory -Force ci-manifests | Out-Null

                [System.IO.File]::WriteAllText(
                    "ci-manifests/deployment.yaml",
                    $manifest,
                    [System.Text.UTF8Encoding]::new($false)
                )

                Write-Host "Prepared local Minikube deployment manifest."
                '''
            }
        }

        stage('Config Scan - Kubernetes') {
            steps {
                bat '''
                docker run --rm -v "%WORKSPACE%:/src" bridgecrew/checkov:latest ^
                  -f /src/ci-manifests/deployment.yaml ^
                  --framework kubernetes --quiet --compact
                '''
            }
        }

        stage('Deploy to TEST') {
            steps {
                withCredentials([
                    file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')
                ]) {
                    powershell '''
                    $ErrorActionPreference = "Stop"

                    kubectl get nodes
                    if ($LASTEXITCODE -ne 0) {
                        throw "Kubernetes connection failed"
                    }

                    kubectl apply -f k8s/app/pvc.yaml -n health-test
                    if ($LASTEXITCODE -ne 0) {
                        throw "TEST PVC deployment failed"
                    }

                    kubectl apply -f k8s/app/service.yaml -n health-test
                    if ($LASTEXITCODE -ne 0) {
                        throw "TEST Service deployment failed"
                    }

                    kubectl apply -f ci-manifests/deployment.yaml -n health-test
                    if ($LASTEXITCODE -ne 0) {
                        throw "TEST Deployment failed"
                    }

                    kubectl rollout status deployment/health-api -n health-test --timeout=180s
                    if ($LASTEXITCODE -ne 0) {
                        throw "TEST rollout failed"
                    }

                    kubectl get pods -n health-test
                    '''
                }
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                powershell '''
                $ErrorActionPreference = "Stop"

                New-Item -ItemType Directory -Force zap-out | Out-Null

                $pf = Start-Process kubectl `
                    -ArgumentList "port-forward -n health-test svc/health-api 8000:80" `
                    -PassThru -WindowStyle Hidden

                try {
                    Start-Sleep -Seconds 5

                    Write-Host "Starting OWASP ZAP baseline scan..."

                    # Allow Docker's native output and capture its exit code.
                    $ErrorActionPreference = "Continue"

                    docker run --rm -v "$($env:WORKSPACE -replace '\\','/')/zap-out:/zap/wrk" `
                        ghcr.io/zaproxy/zaproxy:stable `
                        zap-baseline.py -t http://host.docker.internal:8000 `
                        -r zap-report.html

                    $zapExit = $LASTEXITCODE

                    Write-Host "OWASP ZAP exit code: $zapExit"

                    if ($zapExit -eq 1 -or $zapExit -ge 3) {
                        throw "OWASP ZAP security scan failed with exit code $zapExit"
                    }

                    if ($zapExit -eq 2) {
                        Write-Warning "OWASP ZAP found warnings. Review the archived report."
                    }

                    if ($zapExit -ne 0 -and $zapExit -ne 2) {
                        throw "Unexpected OWASP ZAP exit code: $zapExit"
                    }

                    # Prevent an accepted ZAP warning code from propagating.
                    $global:LASTEXITCODE = 0

                    Write-Host "OWASP ZAP scan completed. Continuing pipeline."
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
                    $ErrorActionPreference = "Stop"

                    $deployment = Get-Content ci-manifests/deployment.yaml -Raw

                    $deployment = $deployment.Replace(
                        "namespace: health-test",
                        "namespace: health-prod"
                    )

                    $service = Get-Content k8s/app/service.yaml -Raw

                    $service = $service.Replace(
                        "namespace: health-test",
                        "namespace: health-prod"
                    )

                    [System.IO.File]::WriteAllText(
                        "deployment-prod.yaml",
                        $deployment,
                        [System.Text.UTF8Encoding]::new($false)
                    )

                    [System.IO.File]::WriteAllText(
                        "service-prod.yaml",
                        $service,
                        [System.Text.UTF8Encoding]::new($false)
                    )

                    kubectl apply -f k8s/app/pvc.yaml -n health-prod
                    if ($LASTEXITCODE -ne 0) {
                        throw "PROD PVC deployment failed"
                    }

                    kubectl apply -f service-prod.yaml -n health-prod
                    if ($LASTEXITCODE -ne 0) {
                        throw "PROD Service deployment failed"
                    }

                    kubectl apply -f deployment-prod.yaml -n health-prod
                    if ($LASTEXITCODE -ne 0) {
                        throw "PROD Deployment failed"
                    }

                    kubectl rollout status deployment/health-api -n health-prod --timeout=180s
                    if ($LASTEXITCODE -ne 0) {
                        throw "PROD rollout failed"
                    }

                    kubectl get pods -n health-prod
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
