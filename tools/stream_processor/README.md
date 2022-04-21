# auth_credentials_generator.py

`auth_credentials_generator.py` is a tool that is created for generating credentials of dynamic stream processor feature.

```console
$ python3 ../tools/stream_processor/auth_credentials_generator.py --credentials-pair <username>:<password> <username2>:<password2> > generated_credentials.conf
```

Then, `generated_credentials.conf` will be:

```log
[AUTH]
    user user
    password <sha512 hashed string>

[AUTH]
    user user1
    password <sha512 hashed string>

```
