#!/bin/bash

rootDir=`pwd`

# the find command will produce all directories in this tree but the .git one.
# Explanation: "-path .git" will select the .git path, passing it to -prune
#              to ignore all of its subtree; -o indicates an or condition, and
#              finally, -type d -print shows only the rest of the directories:
for i in $(find .  \( -path ./.git \) -prune -o -type d -print); do
    cd $i
    ctags -R $rootDir /usr/include
    cd -
done
