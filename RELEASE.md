# Release Process

```
export VSN="<NEW VERSION NUMBER>"

echo $VSN > VERSION
sed "s/^VERSION =.*/VERSION = '$VSN'/g" -i exosite.py

git add exosite.py
git commit -m "Version $VSN"
git tag $VSN -m ""
git push origin
git push --tags origin

# Release on pypi
python setup.py register sdist upload
```
