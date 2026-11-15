
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

        stage('Push Image and Capture Digest') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'dockerhub',
                        usernameVariable: 'DH_USER',
                        passwordVariable: 'DH_PASS'
                    )
                ]) {
                    powershell '''
                    $ErrorActionPreference = "Stop"

                    Write-Host "Docher Hub username : $env:DH_USER"
                    Write-Host "Docker Hub token present : $([bool])$env:DH_PASS"

                    $LoginOutput = $env:DH_PASS |docker login --username $env:DH_USER --password-stdin 2>&1
                    $loginExit = $LASTEXITCODE

                    $loginOutput | ForEach-Object { Write-Host $_ }

                    if ($loginExit -ne 0) {
                        throw "Docker Hub login failed with exit code $loginExit"
                    }

                    try {
                        $pushOutput = & docker push $env:IMAGE 2>&1
                        $pushExit = $LASTEXITCODE

                        $pushOutput | ForEach-Object { Write-Host $_ }

                        if ($pushExit -ne 0) {
                            throw "Docker image push failed"
                        }

                        $digest = $null

                        foreach ($line in $pushOutput) {
                            if ("$line" -match 'digest:\s*(sha256:[0-9a-f]{64})') {
                                $digest = $Matches[1]
                            }
                        }

                        if (-not $digest) {
                            throw "Could not retrieve Docker image digest"
                        }

                        $imageRef = "$env:DH_USER/health-api@$digest"

                        [System.IO.File]::WriteAllText(
                            "image-ref.txt",
                            $imageRef,
                            [System.Text.Encoding]::ASCII
                        )

                        Write-Host "Image digest captured successfully."
                        Write-Host $imageRef
                    }
                    finally {
                        docker logout
                    }
                    '''
                }

                script {
                    env.IMAGE_REF = readFile('image-ref.txt').trim()
                    echo "Immutable deployment image: ${env.IMAGE_REF}"
                }
            }
        }

        stage('Prepare Kubernetes Manifest') {
            steps {
                powershell '''
                $ErrorActionPreference = "Stop"

                $manifest = Get-Content k8s/app/deployment.yaml -Raw

                $manifest = $manifest.Replace(
                    "health-api:local",
                    $env:IMAGE_REF
                )

                if ($manifest -notmatch [regex]::Escape($env:IMAGE_REF)) {
                    throw "Digest image replacement failed"
                }

                New-Item -ItemType Directory -Force ci-manifests | Out-Null

                [System.IO.File]::WriteAllText(
                    "ci-manifests/deployment.yaml",
                    $manifest,
                    [System.Text.UTF8Encoding]::new($false)
                )
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

                    kubectl apply -f k8s/app/pvc.yaml -n health-test
                    if ($LASTEXITCODE -ne 0) { throw "TEST PVC failed" }

                    kubectl apply -f k8s/app/service.yaml -n health-test
                    if ($LASTEXITCODE -ne 0) { throw "TEST Service failed" }

                    kubectl apply -f ci-manifests/deployment.yaml -n health-test
                    if ($LASTEXITCODE -ne 0) { throw "TEST Deployment failed" }

                    kubectl rollout status deployment/health-api -n health-test --timeout=180s
                    if ($LASTEXITCODE -ne 0) { throw "TEST rollout failed" }
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

                    docker run --rm -v "${env:WORKSPACE}\\zap-out:/zap/wrk" `
                        ghcr.io/zaproxy/zaproxy:stable `
                        zap-baseline.py -t http://host.docker.internal:8000 `
                        -r zap-report.html

                    $zapExit = $LASTEXITCODE

                    if ($zapExit -eq 1 -or $zapExit -ge 3) {
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
                    if ($LASTEXITCODE -ne 0) { throw "PROD PVC failed" }

                    kubectl apply -f service-prod.yaml -n health-prod
                    if ($LASTEXITCODE -ne 0) { throw "PROD Service failed" }

                    kubectl apply -f deployment-prod.yaml -n health-prod
                    if ($LASTEXITCODE -ne 0) { throw "PROD Deployment failed" }

                    kubectl rollout status deployment/health-api -n health-prod --timeout=180s
                    if ($LASTEXITCODE -ne 0) { throw "PROD rollout failed" }
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
