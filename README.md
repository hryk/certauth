certauth
--------

Certificate-based authentication backend

### Development (with Vagrant)

#### Setting up VM

First, `vagrant up` create vm and install dependent packages with apt. To
contiue setup, log into vm via `vagrant ssh` and move to `/vagrant` dir.

#### Setting up virtualenv

```
$ pwd
=> /vagrant
$ virtualenv env
$ . env/bin/activate
(env)$ pip install -r requirements.txt
```

#### Create CA key and certificate

```
$ openssl genrsa -out ca.key 2048
$ openssl req -x509 -new -nodes -key ca.key -days 1024 -out ca.crt 
```

#### Start certauth server

```
(env)$ python certauth.py --server
```

To use gunicorn or other wsgi servers,

```
(env)$ gunicorn certauth:app
```

### Request certification

### Sign certification

