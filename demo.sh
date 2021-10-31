#!/bin/bash


# get SBOM of base image
# syft packages registry1.dso.mil/ironbank/elastic/eck-operator/eck-operator:1.7.1 -o cyclonedx > eck-operator.1.7.1.cyclonedx.bom  

# docker build . -t extension:1.7.1

# syft packages extension:1.7.1 -o cyclonedx > extension.1.7.1.cyclonedx.bom


API_KEY=CmdepglbGeC4m9UEDz7kAWrPqc1FUkWu 

URL=https://dep-api.bigbang.dev

# What should we do with the justified vulnerabilities
# in MR, keep as IN_TRIAGE
# if main branch, set to NOT_AFFECTED
APPROVAL=$1
APPROVAL=${APPROVAL:=IN_TRIAGE}

# Vulnerability State


# State	Description
# IN_TRIAGE	The vulnerability has a proposed justification in a MR
# FALSE_POSITIVE	The Vulnerability has been justified by the development team and that's been accepted into MR
# NOT_AFFECTED	The vulnerablity is justified by inheritance from an approved base image
# NOT_SET	New Vulnerability has been found

lookup () {
    # $1 is the component id
    # $2 is the project you'd like to find it in

    # 
    src_purl=`curl -s ${URL}/api/v1/component/$1 \
    -H 'Content-Type: multipart/form-data' \
    -H "X-Api-Key: ${API_KEY}" | jq -r '.purl'`

    curl -s ${URL}/api/v1/component/identity?purl=${src_purl} \
        -H "X-Api-Key: ${API_KEY}" | jq -r '.[] | select( .project.uuid=="'$2'") | .uuid'

}


lookup_vuln_for_component () {
    # $1 component
    # $2 vuln name

     curl -s "${URL}/api/v1/vulnerability/component/$1?searchText=$2" \
     -H "X-Api-Key: ${API_KEY}" | jq -r '.[0].uuid'
}

lookup_name_version () {
    # $1 is the name of the component
    # $2 is the version of the component
    # $3 is the project you'd like to find it in

    # 

    curl -s "${URL}/api/v1/component/identity?name=$1&version=$2" \
     -H "X-Api-Key: ${API_KEY}" | jq -r '.[] | select( .project.uuid=="'$3'") | .uuid'
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


# Upload the SBOM for the base image

# curl -X "POST" "${URL}/api/v1/bom"    \
#     -H 'Content-Type: multipart/form-data' \
#     -H "X-Api-Key: ${API_KEY}" \
#     -F "autoCreate=true" \
#     -F "projectName=ironbank/eck-operator" \
#     -F "projectVersion=1.7.1" \
#     -F "bom=@eck-operator.1.7.1.cyclonedx.bom"

# Upload the new SBOM
# curl -X "POST" "${URL}/api/v1/bom"    \
#     -H 'Content-Type: multipart/form-data' \
#     -H "X-Api-Key: ${API_KEY}" \
#     -F "autoCreate=true" \
#     -F "projectName=extension-image" \
#     -F "projectVersion=1.7.1" \
#     -F "bom=@extension.1.7.1.cyclonedx.bom"

# For everything in the ironbank/eck-operator project, we accept those
# since they're from IronBank

base_project_uuid=`curl -s -X "GET" "${URL}/api/v1/project?name=ironbank/eck-operator"   \
    -H 'Content-Type: application/json' \
    -H "X-Api-Key: ${API_KEY}"  | jq -r '.[0].uuid'`

extension_project_uuid=`curl -s -X "GET" "${URL}/api/v1/project?name=extension-image"   \
    -H 'Content-Type: application/json' \
    -H "X-Api-Key: ${API_KEY}"  | jq -r '.[0].uuid'`

echo "Base project uuid: ${base_project_uuid}"
echo "Extension project uuid: ${extension_project_uuid}"



# For each vuln in the base_project_id, we provide a justification for it
# since itw as approved by Ironbank


# Get all vulns for the base component
vulns=`curl -s https://dep-api.bigbang.dev/api/v1/vulnerability/project/${base_project_uuid}?suppressed=true \
    -H 'Content-Type: application/json' \
    -H "X-Api-Key: ${API_KEY}"  | jq -cr '.[] | {uuid:.uuid,component:.components[0].uuid}'`

# mark each vulnerability for the approved base image as FALSE_POSITIVE since
# they were vettted in Ironbank
for vuln in ${vulns}; do
    component=`echo ${vuln} | jq -r '.component'`
    uuid=`echo ${vuln} | jq -r '.uuid'`
    # These are iron bank images, so everything is good!
    curl -s "${URL}/api/v1/analysis" \
      -X PUT \
      -H 'Content-Type: application/json' \
      -H "X-Api-Key: ${API_KEY}" \
      -d '{
        "project": "'${base_project_uuid}'",
        "component": "'${component}'",
        "vulnerability": "'${uuid}'",
        "analysisState": "FALSE_POSITIVE",
        "comment": "Approved in IronBank",
        "suppressed": true
    }'
done


# Look through all vulnerabilities in the base image
# and mark those as NOT_EFFECTED since they were approved already
for vuln in ${vulns}; do
    echo ${vuln}
    base_component=`echo ${vuln} | jq -r '.component'`
    uuid=`echo ${vuln} | jq -r '.uuid'`
    component=`lookup ${base_component} ${extension_project_uuid}`
    echo "Updating component ${component} in project ${extension_project_uuid}"
    # These are iron bank images, so everything is good!
    curl -s "${URL}/api/v1/analysis" \
      -X PUT \
      -H 'Content-Type: application/json' \
      -H "X-Api-Key: ${API_KEY}" \
      -d '{
        "project": "'${extension_project_uuid}'",
        "component": "'${component}'",
        "vulnerability": "'${uuid}'",
        "analysisState": "NOT_AFFECTED",
        "comment": "Vulnerablity justified by inheriting justification from base image",
        "suppressed": true
    }'
done




# look at the local justifications file


justifications=`yq -j eval justifications.yaml | jq -c -r '.justifications[]'`
IFS=$'\n'



for just in ${justifications}; do
    # get the component
    name=`echo ${just} | jq -r .component`
    version=`echo ${just} | jq -r .version`
    cve=`echo ${just} | jq -r .cve`
    comment=`echo ${just} | jq -r .justification`

    echo "${name}/${version}/${cve}"
    component=`lookup_name_version  "${name}" "${version}" "${extension_project_uuid}"`
    echo "Component: ${component}"
    # get the vuln for the component

    vuln=`lookup_vuln_for_component ${component} ${cve}`
    echo "Vulnerability: ${vuln}"
    # set the analysis
    # These are iron bank images, so everything is good!

    curl -s "${URL}/api/v1/analysis" \
      -X PUT \
      -H 'Content-Type: application/json' \
      -H "X-Api-Key: ${API_KEY}" \
      -d '{
        "project": "'${extension_project_uuid}'",
        "component": "'${component}'",
        "vulnerability": "'${vuln}'",
        "analysisState": "'${APPROVAL}'",
        "comment": "'${comment}'"
    }'

done




# check the project

# for each un suppressed vulnerability that's high or critical,
# get the analysis report
# and make sure the  state is "IN_TRIAGE", "NOT_EFFECTED", or "FALSE_POSITIVE"

# Get all vulns for the base component
IFS=$'\n'
ext_vulns=`curl -s https://dep-api.bigbang.dev/api/v1/vulnerability/project/${extension_project_uuid} \
    -H 'Content-Type: application/json' \
    -H "X-Api-Key: ${API_KEY}"  | jq -c -r '.[] | select( .severity=="CRITICAL" or .severity=="HIGH" ) | { uuid:.uuid, cve:.vulnId, severity: .severity, component: .components[0].uuid}'`


for vuln in ${ext_vulns}; do
    echo ${vuln}
    uuid=`echo ${vuln} | jq -r .uuid`
    component=`echo ${vuln} | jq -r .component`
    echo "Vuln ${uuid} for ${component}"
    lookup_analysis_state ${uuid} ${component}
    # analysis=`lookup_analysis_state ${uuid} ${component}`
    # echo ${}
done