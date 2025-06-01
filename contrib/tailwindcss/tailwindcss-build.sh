#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

if [[ "${BASH_TRACE:-0}" == "1" ]]; then
    set -o xtrace
fi

cd "$(dirname "$0")"

if [[ ! -d "node_modules" ]]
then
    npm install -D tailwindcss
    npm install -D minify
fi

if [[ ! -f "package-lock.json" ]]
then
    npm install -D @tailwindcss/cli
fi

rm ./../../source/internal/workers/http_server_portal_worker/webroot/static/css/base.css || true
npx @tailwindcss/cli --input ./input.css --output ./../../source/internal/workers/http_server_portal_worker/webroot/static/css/base.css --watch
#npx @tailwindcss/cli --input ./input.css --output ./../../webroot/static/css/base.css --watch

