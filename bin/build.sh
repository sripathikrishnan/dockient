# First, create a version.html
commit_id=$(git rev-parse HEAD)
build_time=$(date)
version=$(cat version.txt)

# replace spaces in version
version=${version// /.}

cat << EOF > public/version.html
<html>
    <head><title>Version $version</title></head>
    <body>
        <dl>
            <dt>Version</dt>
            <dd>$version</dd>
            <dt>Build Timestamp</dt>
            <dd>$build_time</dd>
            <dt>Git Commit ID</dt>
            <dd>$commit_id</dd>
        </dl>
    </body>
</html>
EOF

# Then, build the docker image

docker build -t todoapp:$version .