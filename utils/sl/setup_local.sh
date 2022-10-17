#!/bin/bash
# Copyright 2016-2022 Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted for any purpose (including commercial purposes)
# provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions, and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions, and the following disclaimer in the
#    documentation and/or materials provided with the distribution.
#
# 3. In addition, redistributions of modified forms of the source or binary
#    code must carry prominent notices stating that the original code was
#    changed and the date of the change.
#
#  4. All publications or advertising materials mentioning features or use of
#     this software are asked, but not required, to acknowledge that it was
#     developed by Intel Corporation and credit the contributors.
#
# 5. Neither the name of Intel Corporation, nor the name of any Contributor
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This script sets up the PATH environment variable after a local
# coral build.   It uses the .build_vars*.sh script generated by a build
# to setup bin directories for the built component and its prerequisites.
# The generated script sets SL_[prereq]_PREFIX for all prerequisites and
# SL_PREFIX for the component itself.  Additionally, it exports unique
# SL_*PREFIX variables to be used by component specific wrapper scripts
# to setup things like PYTHONPATH, CPATH, LIBRARY_PATH, as needed.

echo "$PWD"
VARS_FILE=".build_vars-$(uname -s).sh"
VARS_FILE2=.build_vars.sh
if [ -f "./${VARS_FILE}" ]; then
  VARS_LOCAL="./${VARS_FILE}"
elif [ -f "../${VARS_FILE}" ]; then
  VARS_LOCAL="../${VARS_FILE}"
elif [ -f "./${VARS_FILE2}" ]; then
  VARS_LOCAL="./${VARS_FILE2}"
elif [ -f "../${VARS_FILE2}" ]; then
  VARS_LOCAL="../${VARS_FILE2}"
else
  VARS_LOCAL=""
fi

if [ -z "${VARS_LOCAL}" ]
then
    echo "Build vars file ${VARS_FILE} does not exist"
    echo "Cannot continue"
    return 1
fi

echo "Build vars file found: ${VARS_LOCAL}"
. ${VARS_LOCAL}

os="$(uname)"
if [ "$os" = "Darwin" ]; then
    if [ -n "$DYLD_LIBRARY_PATH" ]; then
	export DYLD_LIBRARY_PATH=${SL_LD_LIBRARY_PATH}:${DYLD_LIBRARY_PATH}
    else
	export DYLD_LIBRARY_PATH=${SL_LD_LIBRARY_PATH}
    fi
fi

if [ -z "${SL_PREFIX}" ]
then
    SL_PREFIX="$(pwd)/install"
fi

function export_pythonpath()
{
  MAJOR="${1}"
  MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
  VERSION="${MAJOR}.${MINOR}"
  if [ "${MAJOR}" -eq 3 ]; then
    PYTHONPATH=${SL_PREFIX}/lib64/python${VERSION}/site-packages:${PYTHONPATH}
  else
    echo "unknown Python version: ${VERSION}"
    return 0
  fi

  export PYTHONPATH
}

# look for a valid installation of python
if [ -x "$(command -v python3)" ]; then
  PYTHON_VERSION="$(python3 -c 'import sys; print(sys.version_info.major)')"
  export_pythonpath "${PYTHON_VERSION}"
else
  echo "python3 not found"
fi

function in_list()
{
    this=$1
    shift
    for dir in "$@"; do
        if [ "$dir" == "$this" ]; then
            return 1
        fi
    done
    return 0
}

function create_list()
{
  compgen -A variable | grep "SL_.*_PREFIX"
}

list="$(create_list)"
# skip the default paths
added="/ /usr /usr/local"
old_path="${PATH//:/ }"
echo OLD_PATH is "${old_path}"
for item in $list; do
    in_list "${!item}" "${added}"
    if [ $? -eq 1 ]; then
        continue
    fi
    export ${item}
    added+=" ${!item}"
    in_list "${!item}/bin" "${old_path}"
    if [ $? -eq 1 ]; then
        continue
    fi
    if [ -d "${!item}/bin" ]; then
        PATH=${!item}/bin:$PATH
    fi
done

in_list "${SL_PREFIX}/bin" "${old_path}"
if [ $? -eq 0 ]; then
    PATH=$SL_PREFIX/bin:$PATH
fi
export PATH
export SL_PREFIX
export SL_SRC_DIR
