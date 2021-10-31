#!/bin/bash

API_KEY=CmdepglbGeC4m9UEDz7kAWrPqc1FUkWu 

URL=https://dep-api.bigbang.dev
APPROVAL=$1
APPROVAL=${APPROVAL:=IN_TRAIGE}

lookup () {
    # $1 is the component id
    # $2 is the project you'd like to find it in

    # 
    src_purl=`curl -s ${URL}/api/v1/component/$1 \
    -H 'Content-Type: multipart/form-data' \
    -H "X-Api-Key: ${API_KEY}" | jq -r '.purl'`

    curl -s ${URL}/api/v1/component/identity?purl=${src_purl} \
        -H "X-Api-Key: ${API_KEY}" | jq -r '.[] | select( .project.uuid=="'$2'") | .uuid'

#https://dep-api.bigbang.dev/api/v1/component/identity?cpe=&group=&name=&purl=pkg%3Agolang%2Fgithub.com%2Fgogo%2Fprotobuf%40v1.3.2&swidTagId=&version=
    # echo "Hello component $1 has purl = ${src_purl}"
}

lookup_name_version () {
    # $1 is the name of the component
    # $2 is the version of the component
    # $3 is the project you'd like to find it in

    # 

    curl -s "${URL}/api/v1/component/identity?name=$1&version=$2" \
     -H "X-Api-Key: ${API_KEY}" | jq -r '.[] | select( .project.uuid=="'$3'") | .uuid'

#https://dep-api.bigbang.dev/api/v1/component/identity?cpe=&group=&name=&purl=pkg%3Agolang%2Fgithub.com%2Fgogo%2Fprotobuf%40v1.3.2&swidTagId=&version=
    # echo "Hello component $1 has purl = ${src_purl}"
}


lookup_vuln_for_component () {
    # $1 component
    # $2 vuln name

     curl -s "${URL}/api/v1/vulnerability/component/$1?searchText=$2" \
     -H "X-Api-Key: ${API_KEY}" | jq -r '.[0].uuid'
}


lookup_analysis_state () {
    # $1 vuln_uuid
    # $2 component_uuid
    
    # get the projectID from the component

    project_uuid=`curl -s ${URL}/api/v1/component/$2 \
     -H "X-Api-Key: ${API_KEY}" | jq -r .project.uuid`
    echo "Project =  ${project_uuid}"

    curl -s "${URL}/api/v1/analysis?component=$2&project=$project_uuid&vulnerability=$1" \
        -H "X-Api-Key: ${API_KEY}"
}


# lookup "20c08ca1-6e25-495a-b698-705a195d6f2f" "86373bc1-0df7-4379-ac7b-cf7cf15ac899"

# echo "Correct answer should be 4a9fb5b8-805b-4b80-8d3d-4405c0d554d1"

# lookup_name_version  "php-frontend" "3.17.0.7439" "86373bc1-0df7-4379-ac7b-cf7cf15ac899"


# justifications=`yq -j eval justifications.yaml | jq -c -r '.justifications[]'`
# IFS=$'\n'



# lookup_vuln_for_component 99e2b15b-5c03-40bf-b5ce-33b373675aa7 CVE-2014-9912
# echo "Should be 1f97963d-fbb5-4902-9563-fd956ab6946d"

lookup_analysis_state 772f8953-46b4-4847-8684-ede1f62f830f c80a5f04-1d2a-491c-8074-3255628cda79
lookup_analysis_state 1f97963d-fbb5-4902-9563-fd956ab6946d c80a5f04-1d2a-491c-8074-3255628cda79