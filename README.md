# collector-harbor

## Running Harbor locally
Follow along [this blog](https://serverascode.com/2020/04/28/local-harbor-install.html) to setup Harbor locally using Docker Desktop and Helm.

You can then navigate to https://core.harbor.domain/harbor to access the console.
The default admin credentials are:
```
username: admin
password: Harbor12345
```

## Pushing an image to Harbor

Heres an example of pushing the nginx image to the default `library` project:
```
docker pull nginx:stable-alpine
docker tag nginx:stable-alpine core.harbor.domain/library/nginx:stable-alpine
docker push core.harbor.domain/library/nginx:stable-alpine
```

Read more about how to setup Webhooks for projects [here](https://goharbor.io/docs/2.1.0/working-with-projects/project-configuration/configure-webhooks/).

## Running Harbor Collector locally

Build and deploy the Harbor Collector:
```
docker build -t rode-collector-harbor .
helm install rode-collector-harbor charts/rode-collector-harbor --set=image.repository=rode-collector-harbor --set=image.tag=latest
```

Watch the pod logs:
```
export POD_NAME=$(kubectl get pods --namespace default -l "app.kubernetes.io/name=rode-collector-harbor,app.kubernetes.io/instance=rode-collector-harbor" -o jsonpath="{.items[0].metadata.name}")
kubectl logs $POD_NAME
```
