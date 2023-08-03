Purpose of this directory is to leverage https://github.com/danielfett/sd-jwt

to ensure cross testing is as easy as possible.


Run these commands from the root directory of the project:

```
cd interop
git clone git@github.com:danielfett/sd-jwt.git
```

```
python3 -m venv venv
source venv/bin/activate
```

```
cd interop/sd-jwt/tests/testcases
sd-jwt-generate example
```

This will refresh the test cases...

Copy those test cases out of the git repo so they can be commited / used by CI.

