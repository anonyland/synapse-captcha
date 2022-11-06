## Synapse-Captcha

A custom captcha for Synapse.
Disable registration in ``homeserver.yaml``

### Building
``
git clone https://git.anonymousland.org/anonymousland/synapse-captcha/
``

``
cd synapse-captcha
``

``
docker build .
``

Modify `config.sample.yaml` to your needs and save as `config.yaml`
The `shared_secret` can be found in `homeserver.yaml`.


Redirect to your docker installation:

(Modify for your needs)
```
    location /register {
        include /config/nginx/proxy.conf;
        include /config/nginx/resolver.conf;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        set $upstream_app matrix-registration;
        set $upstream_port 5000;
        set $upstream_proto http;
        proxy_pass $upstream_proto://$upstream_app:$upstream_port;
    }
```

ex. `matrix.example.tld/register`

Docker-compose example:

```
    build: ./images/synapse-captcha
    container_name: matrix-registration
    restart: always
    command: [
                "--config-path=/data/config.yaml",
                "serve"
            ]
    ports:
      - 127.0.0.1:5000:5000
    volumes:
      - ./matrix-registration_data:/data:Z
    networks:
      - matrix
```