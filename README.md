# Simple GO CRUD REST API with Microservice Implementation

This is a simple GO CRUD REST API with microservice implementation written as a part of hiring process for the Site Reliability Enginneer Role at Deall.

Normally, each microservice would be pushed to different repositories, but for simplicity sake this repository will contain all the microservices used in the API.

This REST API is meant to be deployed to Kubernetes using Jenkins. But you could also simply install each microservice using Helm to Kubernetes.

# Installation
> Please do note that the following instructions was made to Install the API on a Google Kubernetes Engine
## Install

    git clone https://github.com/kdknive/deall-coding-test
    helm install ms-go-auth ms-go-auth/helm/ms-go-auth -n coding-test --create-namespace
    helm install ms-go-crud ms-go-crud/helm/ms-go-crud -n coding-test 
    
## Get Ingress ExternalIP
> If the following command resulted an Error you probably haven't installed NGINX Ingress Controller on your Kubernetes. (see [NGINX Ingress GKE](https://pages.github.com/) for reference)

    export NGINX_INGRESS_IP=$(kubectl get service nginx-ingress-ingress-nginx-controller -n nginx -ojson | jq -r '.status.loadBalancer.ingress[].ip')
    echo $NGINX_INGRESS_IP

## Test the IP

    ping $NGINX_INGRESS_IP

# REST API

Below are the detailed information of the REST API's endpoints to be tested using Postman.

> This is the default credentials for the first Admin <br> username : admin <br> password : admin123

<table>
<tr>
<th> Method </th> <th> Endpoint </th> <th> Header </th> <th> Body </th> <th> Description </th>
</tr>
<tr>
<td> POST </td>
<td> /admin/first </td>
<td> None </td>
<td> None </td>
<td> Can only be used once to create the first Admin </td>
</tr>
<tr>
<td> POST </td>
<td> /admin </td>
<td> Authorization : &lt;JWT Token&gt;</td>
<td>
    
```json
{
    "name": "example admin",
    "username": "exampleadmin",
    "email": "exampleadmin@gmail.com",
    "password": "exampleadmin"
}
```

</td>
<td> Create Admin <br> Requires Admin's JWT Token </td>
</tr>
<tr>
<td> POST </td>
<td> /user </td>
<td> None </td>
<td>
    
```json
{
    "name": "example",
    "username": "example",
    "email": "example@gmail.com",
    "password": "example"
}
```

</td>
<td> Create User <br> Can be done without any Token <br> Can't use the same username and email as other users</td>
</tr>
<tr>
<td> GET </td>
<td> /user/&lt;username&gt; </td>
<td> Authorization : &lt;JWT Token&gt;</td>
<td> None </td>
<td> Get user data <br> Admin's JWT Token can get any user data <br> User's JWT Token can only get their own data </td>
</tr>
<tr>
<td> PUT </td>
<td> /user/&lt;username&gt; </td>
<td> Authorization : &lt;JWT Token&gt;</td>
<td>
    
```json
{
    "role": "user", //only applicable for Admins
    "name": "example edited", 
    "username": "example",
    "email": "example@gmail.com",
    "password": "example"
}
```

</td>
<td> Update user data <br> Admin's JWT Token can update any user data <br> User's JWT Token can only update their own data <br> Can't update if the username and email is the same as other users <br> Updating the role is only applicable for Admins, the API won't read the "role" key if the JWT Token belongs to a user </td>
</tr>
<tr>
<td> DELETE </td>
<td> /user/&lt;username&gt; </td>
<td> Authorization : &lt;JWT Token&gt;</td>
<td> None </td>
<td> Delete user data <br> Admin's JWT Token can delete any user data <br> User's JWT Token can only delete their own data </td>
</tr>
<tr>
<td> GET </td>
<td> /users </td>
<td> Authorization : &lt;JWT Token&gt;</td>
<td> None </td>
<td> Get all user data <br> Only Admin's JWT Token can get all user data </td>
</tr>
<tr>
<td> POST </td>
<td> /login </td>
<td> None </td>
<td>
    
```json
{
    "username": "example",
    "password": "example"
}
```

</td>
<td> Admin/User Login <br> Login to get JWT Token </td>
</tr>
<tr>
<td> GET </td>
<td> /auth </td>
<td> Authorization : &lt;JWT Token&gt;</td>
<td> None </td>
<td> Validate Token <br> Check the validity of JWT Token </td>
</tr>
</table>

# REST API Flow Diagram

The flow of this REST API is fairly simple. Clients can make requests to the API, and based on the Endpoint, the API will require you to provide JWT Token that can be acquired by using the `/login` endpoint.

The `/login` and `/auth` endpoint will be handled by `ms-go-auth` microservice while the others will be handled by `ms-go-crud`.

When an endpoint require the client to provide a JWT Token, `ms-go-crud` will access the `/auth` endpoint on `ms-go-auth` to authenticate the client. And if `ms-go-auth` responded with Status `200`, the API will respond with the approriate response.

![REST API Flow Diagram](/rest-api-flow.png)

# CI/CD Pipeline

Here is the diagram of the CI/CD Pipeline used to deploy this REST API. The platform used for this pipeline is GCP with Google Kubernetes Engine (GKE) as the Kubernetes cluster.

Jenkins is used to automate the delivery of the microservices and was deployed on Kubernetes using Helm.

First when a developer pushed some changes to GitHub, it will send a webhook to Jenkins which will then start the building process of the microservice using the Jenkinsfile on the repository.

The Jenkinsfile will then create a Jenkins Agent pod on Kubernetes that will have Google Cloud Build container and Helm container. The Google Cloud Build container will be used to build the Dockerfile of the microservice and then push it to the Artifact Registry on GCP.

After that, the Helm container will use the Helm Chart of the microservice and use the Docker Image previously pushed to the Artifact Registry to finally install the microservice on Kubernetes.

![CI/CD Pipeline](/cicd-pipeline.png)