# Python3 new one
def main():
    import docker

    case = docker.from_env()

    conts = [cont for cont in case.containers.list(all)]
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        for idx,cont in enumerate(conts):
            print("{}) {} <{}>".format(idx+1, cont.name, cont.short_id))

        choice = input("Detail which container")
        if choice == 0:
            break
        else:
            ct = conts[choice-1]
            print("Container Name & <ID>: {name} <{id}>\n \
                   Image & <Status>: {image} <{status}> \
                   Processes: {top}".format(name=ct.name,id=ct.short_id,
                                            image=ct.image,status=ct.status,
                                            top=ct.top))
        input("Return to home")


main()
