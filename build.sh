#!/usr/bin/env bash
set -e

if [ "$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then
	echo "You are not on the master branch, aborting"
	/bin/false
fi;

export VERSION=$(date "+%Y%m%d.%H%M%S")
export DIST=xenial
export ARCH=amd64
echo "Generating changelog changelog"
gbp dch --debian-tag="%(version)s" --new-version=$VERSION --debian-branch master --release --commit
echo "Building package"
gbp buildpackage --git-pbuilder --git-dist=$DIST --git-arch=$ARCH --git-debian-branch=master
echo "Creating tag $VERSION"
git tag $VERSION
echo "Pushing tags"
git push
git push --tags
