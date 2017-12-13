# Python3 new one

import docker

case = docker.from_env()

conts = [cont for cont in case.containers.list(all)]

for idx,cont in enumerate(conts):
    print("{}) {}".format(idx,val)
