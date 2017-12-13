###########################
##
##	Dockscan Forensic Analysis Tool
##	Jay App Two
##	v.1.0 'Whalefall' release, 12.9.2017
##
##	A forensic tool for the analysis of a mounted disk image 
##	containing a container environment managed by a Docker host
##
##	Point to the docker root directory
##	
##	scripted in Python 2.7
##
#################################################################

import json, os, sys, re, datetime
from glob import glob#pattern matching directories
from collections import Counter#counting lists
from string import printable#printable values

def printerOFF():#redirects stdout to devnull for no output
    sys.stdout = open(os.devnull, 'w')

def printerON():#resets stdout for output
    sys.stdout = sys.__stdout__

def elog(ex):#for logging errors
	pass#uncomment below for debug mode
	#with open('logdockthis.txt', 'a') as mylog:
	#	mylog.write('%s : %s\n' % (datetime.datetime.now(),ex))#writes datetime and the exception to file


def imageScan(host, reco, fs):#begins the search for images on the docker host
	hdict = {}
	hlist = []
	childs = []#these lists/dicts for counting non-shared layers of images
	repoPath = '%s/image/%s/repositories.json' % (host,fs)#sets path for repositories file
	imgs = 0
	lyrs = 0#these are counters for images & layers

	if reco == True:#if user is searching an incomplete docker host
		repoPath = None

	print('')
	print('Now scanning for Docker images using the repositories database...\n')

	try:#for working/valid repositories files
		with open(repoPath) as data:
			g = json.load(data)
			for k in g["Repositories"].keys():#iters through each image in the repositories.json file
				print('The image "%s" was found and has these versions...' % k)
				missing = True#to ensure the image has a version/content associated with it
				for key in g["Repositories"][k].keys():#iters through the versions of each image found
					if '@sha256' in key:#is not related to a specific version, so we ignore it
						pass#do nothing
					else:#this image has a version
						missing = False#version found
						imgs += 1#image found
						sha = g["Repositories"][k][key][7:]#sha256 of this image
						print('*****\n%s\n*****\n' % key)

						(hlist,childs,lyrs) = rawImageScan(host,sha,hlist,lyrs,fs)#call rawImageScan to search for content layers
						hdict.update({key : childs})#remember all child layers belonging to this version

				if missing == True:#no images with tags found
					print('*****\nNo version information found - possible corruption!\n*****\n')
				print("----------------\n")
	
	except Exception as e:#when repositories.json is corrupt/invalid
		elog(e)#error logging
		print('Error parsing repositories database... Performing raw analysis\n')
		print('Now scanning for Docker images in /image/%s/imagedb...\n' % fs)
		for i in glob('%s/image/%s/imagedb/content/sha256/*' % (host,fs)):#perform a directory search for the images
			try:
				with open(i) as data:
					try:
						g = json.load(data)
						if 'config' in g.keys():#get the information for this image, exceptions catch missing keys/invalid json
							imgs += 1
							sha = i.strip('/')[-64:]
							try:
								cmdhint = ' , '.join(g['config']['Cmd'])#hints are possible identifiers as to what the image name might be - if found
							except Exception as e:
								elog(e)
								cmdhint = g['config']['Cmd']
							try:
								enthint = ' , '.join(g['config']['Entrypoint'])
							except Exception as e:
								elog(e)
								enthint = g['config']['Entrypoint']
							try:
								envhint = ' , '.join(g['config']['Env'])
							except Exception as e:
								elog(e)
								envhint = g['config']['Env']
							try:
								auth = g['author']#author info - if found
							except Exception:
								elog(e)
								auth = 'UNKNOWN'
							try:
								crea = g['created']#created data - if found
							except Exception:
								elog(e)
								crea = 'UNKNOWN'

							print('\n*****\nImage found with id "%s"...\nCreated: %s\nAuthor: %s\nIdentified by: %s , %s , %s \n*****\n' % (sha,crea,auth,cmdhint,enthint,envhint))

							(hlist,childs,lyrs) = rawImageScan(host,sha,hlist,lyrs,fs)#again searching for content layers
							hdict.update({sha : childs})#and storing content layer info with the image
							print('----------------\n')

					except Exception as e:
						elog(e)
						pass
			except IOError as e:
				elog(e)
				pass
	count = Counter(hlist)#count the number of layers used in more than one image
	for e in count.keys():#iter through the layers
		if count[e] > 1:
			lyrs -= count[e]-1#if layer is counted more than once, correct the layers counter so it does not count a layer twice
	print('\n')
	return (imgs,lyrs)# returns the counts

def rawImageScan(host,sha,hlist,lyrs,fs):#searches for content layers on the docker host, called by imageScan()
	
	childs = []#counts the other layers for this particular image
	
	try:
		with open('%s/image/%s/imagedb/content/sha256/%s' % (host,fs,sha)) as moda:#this file stores layer info
			j = json.load(moda)
			sha = ''.join(j["rootfs"]["diff_ids"])#reads the sha256 digests in to our string
	
			try:
				with open('%s/image/%s/layerdb/sha256/%s/cache-id' % (host,fs,sha[7:71])) as f:#shortens the string for only the first/base layer
					lyrs += 1#layer counter gets incremented
					f_cont = f.read()#gets the directory which holds the base layer content
					print('The base layer is located at:\ndocker/%s/diff/%s\n' % (fs,f_cont))
					hlist.append(f_cont)#adds this to a running list of all layers found - to count later
					childs.append(f_cont)#adds this to the list of layers  for this image
			except Exception as e:
				print('No base layer for this image!')
			for i in glob('%s/image/%s/layerdb/sha256/*/diff' % (host,fs)):#searches for the other layers of this image
				f = open(i)#opens files one by one
				f_cont = f.read()
				if f_cont in sha[71:]:#cuts out the first/base layer digest, sees if layer at directory corresponds to this image
					lyrs += 1#counter increments
					h = open('%scache-id' % i[:-4])#reads the final location of layer content from this file
					h_cont = h.read()
					print("Child layer found at:\ndocker/%s/diff/%s\n" % (fs,h_cont))
					hlist.append(h_cont)#again adds the new found layer to these running counts
					childs.append(h_cont)
					h.close()
				f.close()
	except Exception as e:#in case no valid data for the image
		elog(e)
		print ('No JSON data available!\n')

	return (hlist, childs, lyrs)#returns the running lists and counter

def containerScan(host,fs):#scans the docker host for containers
	print('')
	print('Now scanning for Docker containers...')
	print('')
	cons = 0#counters to track containers, bits of info and a list for names
	vols = 0
	imgs = 0
	lays = 0
	runs = 0
	nets = 0
	cnames = []

	for i in glob('%s/containers/*/' % host):#iters through directories which store container info
		cid = i.strip('/')[-64:]#sets the container ID
		
		print ('-----\n\nContainer has ID: %s... ' % cid[:16])
		try:
			with open('%s/containers/%s/config.v2.json' % (host,cid)) as data:#opens the container config json
				dup = 0
				try:
					g = json.load(data)
				except Exception as e:
					g = '123456'
					elog(e)
					
				if g == '123456':
					print('Corrupt JSON!')
				else:
					print('General info. '),#displays information from the config file, exceptions catch missing/invalid data
					try:
						if g["Name"] in cnames:#catching duplicate containers
							dup = 1
							print('*DUPLICATE CONTAINER*'),
						else:
							cnames.append(g["Name"])

						print('Name "%s" ' % g["Name"][1:]),
						print('Built from "%s" image' % g["Config"]["Image"])

						if dup == 0:#increment counters if not duplicate
							cons += 1#adds to our container counter
							imgs += 1#adds one to the bits of info counter
					except Exception as e:
						elog(e)
						print('but the name and image name cannot be found')
					try:
						print('Runtime info. '),#displays status info based on truthfulness of this key
						if g["State"]["Running"] == True: 
							print('[Running'),
							pid = g["State"]["Pid"]
							print('PID: %s]' % pid),
						elif g["State"]["Restarting"] == True:
							print('[Restarting]'),
						elif g["State"]["Paused"] == True:
							print('[Paused]'),
						elif g["State"]["RemovalInProgress"] == True:
							print('[Being removed]'),
						else: 
							print("[Stopped]"),
					except Exception as e:
						elog(e)
						print('none available - '),
					try:
						start = ''.join(g["State"]["StartedAt"]).replace('T',' at ')#formats time
						finish = ''.join(g["State"]["FinishedAt"]).replace('T',' at ')
						if g["State"]["Running"] == True:#if the container is running, does not display finish time
							finish = ''
						print(' Started on: *%s*  Finished on: *%s*' % (start[:22],finish[:22]))
						if dup == 0:
							runs += 1

					except Exception as e:
						elog(e)
						print('and corrupt runtime data')
					
					try:
						print('Network info. '),
						net = ''.join(g["NetworkSettings"]["Networks"].keys())
						mac = g["NetworkSettings"]["Networks"][net]["MacAddress"]
						print('MacAddress {%s}  Network name: "%s"  ' % (mac,net)),

						try:#port info can be stored in this key in two ways, exception makes sure both are attempted
							port = ''.join(g["NetworkSettings"]["Ports"].keys())
						except Exception as e:
							elog(e)
							port = g["NetworkSettings"]["Ports"]
						print('IP and exposed ports: %s : %s' % (g["NetworkSettings"]["Networks"][net]["IPAddress"],port))
						if dup == 0:
							nets += 1
					except Exception as e:
						elog(e)
						print('Volume info corrupt')

					try:
						print('Volume info. '),
						if not g["MountPoints"].keys():
							print('No linked volumes'),
						else:
							for i in g["MountPoints"].keys():
								if g["MountPoints"][i]["Type"] == 'bind':
									print('Bind at %s:%s ' % (g["MountPoints"][i]["Source"],g["MountPoints"][i]["Destination"])),
								else:
									print('Storage at %s/_data ' % (g["MountPoints"][i]["Name"][:16])),
						if dup == 0:
							vols += 1
					except Exception as e:
						elog(e)
						print('Volume info corrupt'),
				if dup == 1:
					cnames.append(g["Name"])

		except IOError as e:#when no config file found
			elog(e)
			print('but has no config file!')
		print('')
		try:
			f = open('%s/image/%s/layerdb/mounts/%s/mount-id' % (host,fs,cid))#finds location of top layer for this container
			rwlay = f.read()
			if fs == 'aufs':#storage drivers have different paths to the top layer
				print('Data info. R/W layer is at docker/%s/diff/%s...\n' % (fs,rwlay[:16]))
			else:
				print('Data info. R/W layer is at docker/%s/%s.../diff\n' % (fs,rwlay[:16]))
			f.close()
			if dup == 0:
				lays += 1
		except Exception as e:
			elog(e)
			print('Could not find the read/write layer for this container')
	return (cons,imgs,runs,vols,lays,nets)#returns the counters and maximum

def fileScan(host,fs):#performs a search for all files in container top/RW layers
	print('')
	print('Now scanning for files...')
	print('')
	fils = 0#counter for files found
	seen = []

	for i in glob('%s/containers/*/' % host):#iters through container directories#
		cid = i.strip('/')
		cid = cid[-64:]#gets container ID
		try:
			print ('\n*****\nFor the container running image'),
			with open('%s/containers/%s/config.v2.json' % (host,cid)) as data:#looks in the config file for image name
				g = json.load(data)
				print('"%s" with container-id %s' % (g["Config"]["Image"],cid[:12]))
		except Exception as e:#if image name not found
			elog(e)
			print('*UNKNOWN-IMAGE* container-id is %s' % cid[:12])

		try:
			f = open('%s/image/%s/layerdb/mounts/%s/mount-id' % (host,fs,cid))#finds the directory holding the RW layer
			f_cont = f.read()
			if not f_cont:
				print ('*****\n\nNo pointer to this container r/w layer!')
			else:
				seen.append(f_cont)
				if fs == 'aufs':#since storage drivers have different path to the RW layer
					print('Searching RWlayer for files at docker/aufs/diff/%s...\n*****\n' % f_cont[:16])
					found = dirTree('%s/aufs/diff/%s' % (host,f_cont))#calls dirTree to list the files in this directory, uses found to count
				else:
					print('Searching RWlayer for files at docker/overlay2/%s.../diff/\n*****\n' % f_cont[:16])
					found = dirTree('%s/%s/%s/diff' % (host,fs,f_cont))
				if found == 0:#if no files are found during the search
					print("No files found in this container layer")
				fils += found#adds to the total files found counter
			f.close()
		except Exception as e:
			elog(e)
			print('Could not locate pointer to files')
	print('\n-----\n\nOne last check for top layers...\n')
	if fs == 'aufs':
		diff = '%s/aufs/diff/*/' % host
	else:
		diff = '%s/overlay2/*/' % host
	for i in glob(diff):#iters through r/w layer directories
		if i[-6:].strip('/') == '-init':
			if i[-70:-6] in seen:
				pass
			else:
				if fs == 'aufs':
					print ('*****\nFound RWlayer without pointer at docker/aufs/diff/%s...\n*****\n' % i[-70:-54])
					found = dirTree('%s/aufs/diff/%s' % (host,i[-70:-6]))
				else:
					print ('*****\nFound RWlayer without pointer at docker/overlay2/%s.../diff/\n*****\n' % i[-70:-54])
					found = dirTree('%s/overlay2/%s/diff' % (host,i[-70:-6]))
				fils += found
	print('\n')
	return fils#returns total files found

def volumeScan(host):#perform a search for all volumes and files within on docker host
	print('')
	print('Now scanning for Docker volumes...')
	print('')
	vols = 0#counters for volumes found and volumes w files found
	fils = 0
	print('Found the following volumes:')
	for i in glob('%s/volumes/*/' % host):#iters through volume directories
		match = 0#will flag when a container matches this volume
		vols += 1#volume counter incremented
		myvol = i.replace('%s/volumes/' % host,'')#gets volume ID
		myvol = myvol.strip('/')
		print ('\n*****\ndocker/volumes/%s  Used by container:' % myvol[:16]),
		for j in glob('%s/containers/*/' % host):#iters through container directories
			cid = j.strip('/')
			cid = cid[-64:]#gets container ID
			try:
				with open('%s/containers/%s/config.v2.json' % (host,cid)) as data:#opens container config file
					g = json.load(data)
					try:
						if not g["MountPoints"].keys():#if no mountpoint info is present
							pass
						else:
							for k in g["MountPoints"].keys():#checks all the mountpoints of the container#
								if g["MountPoints"][k]["Name"] == myvol:#if there is a match to the volume we are examining
									match = 1#increment the counter
									print('%s (%s)' % (g["Name"][1:],g["Config"]["Image"])),#
					except Exception as e:#if json is invalid
						elog(e)
						break
			except Exception as e:
				elog(e)
				break
		if match == 0: 
			print('None!'),#if no match to a container, then say so
		print('\n*****\n')
		found = dirTree('%s/volumes/%s' % (host,myvol))#call dirTree to search for files in the volume's directory
		if found == 0: 
			print("No files found in this volume")#if nothing found, then say so
		fils += found#add to total files found counter
		print('')
	return vols, fils#return the counter values

def logScan(host):#search for and display the events log
	print('')
	print('Searching for Docker events log...')
	print('')
	logs = 0
	try:
		with open('%s/var/run/docker/libcontainerd/containerd/events.log' % host) as f:#try to open the events log
			logs += 1
			print('Reading from events log...\n')
			for line in f:#read each line, format them to be readable
				line = line.replace('{"id":"','Deleted: ').replace('","type":"',' ').replace('","timestamp":"',' at ').replace(',"pid":"init"','')
				line = line.replace('start-container','started')
				for i in glob('%s/containers/*/' % host):#get full path to container
					if i[-65:-1] in line:#shorten for ID, see if it matches with this line of the log
						with open('%s/containers/'+ i[-65:-1] + '/config.v2.json' % host) as data:#if it matches, open the config file
							g = json.load(data)#and get the image and name info and add it to each line
							line = line.replace(i[-65:-1], i[-35:-1]+('...')).replace('Deleted:', 'Container: %s (%s)' % (g["Name"][1:],g["Config"]["Image"]))
				print(line[:-16])
	except IOError as e:#if events.log does not exist
		elog(e)
		print('events.log not found!\n')
	print('\n------\nSearching for container logs...\n')

	for i in glob('%s/containers/*/' % host):#iters through directories which store container info
		cid = i.strip('/')[-64:]#sets the container ID
		try:
			with open('%s/containers/%s/%s-json.log' % (host,cid,cid)) as data:#opens the container log file
				print ('Log found for container with ID: %s... ' % cid[:16])
				logs += 1#increments log count by one
		except Exception as e:
			elog(e)
			print ('No logs found for container with ID: %s... ' % cid[:16])
	print('')

	return logs#return logs counter

def networkScan(host):#performs a scan of the network config file
	print('')
	print('Looking at network info...')
	print('')
	nets = -3#counters for networks (minus the three defaults) and connected containers
	conts = 0

	try:
		netd = dictDb('%s/network/files/local-kv.db' % host)#tries to read the file into a dictionary using dictDb() for parsing
	except Exception as e:
		elog(e)
		print('No network file available to read')#when fails
		return (0,0)

	
	for i in netd.keys():#iters through the dict keys
		if '"sandbox"' in netd[i]:#indicates a connected container
			print('*****\nContainer: %s' % i),
			try:
				conts += 1#increments the counter
				temp = netd[i][netd[i].index('"sandbox"')+1]#gets the key of this info set to use...
				print('CID: %s..."' % netd[temp][netd[temp].index('"Cid"')+1][:16]),#to finally get the container ID
				print('IP: %s MAC: {%s}\n*****\n' % (netd[i][netd[i].index('"addr"')+1],netd[i][netd[i].index('"mac"')+1]))
			except Exception as e:
				elog(e)
				print('corrupt data')
		elif '"name"' in netd[i]:#indicates a named network
			print('*****\nNetwork: %s' % i),
			try:
				nets += 1
				if i == '"host"' or i == '"none"':#default networks
					print('(default)\n*****\n')
				else:
					if i == '"bridge"':#default network
						print('(default)'),
					else:#all others must be user created
						print('(user-created)'),
					temp = netd[i][netd[i].index('"id"')+1]#gets the key of this info set,
					subn = netd[temp][netd[temp].index('"AddressIPv4"')+1]#uses it to get the subnet info
					print('Subnet %s0%s\n*****\n' % (subn[:-5],subn[-4:]))
			except Exception as e:
				elog(e)
				print('corrupt data')
	return (nets,conts)#returns our two counters

def dictDb(path):#parses the network database file into readable keys
	with open(path) as file:
			data = file.read()
 			data = ''.join(char for char in data if char in printable)#only leave printable characters
 			data = data.replace('"{"','{"')#to ensure data is between double quotes...
 			data = data.replace('docker/network',' ')#removes that criteria, creates whitespace between sets in the db
 			dlist = data.split()#splits to a list
 			ddict = {}

 			for i in dlist:#gives a name to each set in the db, pushes to a dict in format "set name":[list items]
 				if 'name' in i: #for named networks
					dvals = re.findall('".*?"',i)#reads all info between double quotes into individual list items
					ddict.update({dvals[dvals.index('"name"')+1]:dvals})#stores those list items with the named key
				elif 'Cid' in i:#for connected containers
					dvals = re.findall('".*?"',i)
					ddict.update({dvals[dvals.index('"ID"')+1]:dvals})
				elif 'EnableICC' in i:#more named networks
					dvals = re.findall('".*?"',i)
					ddict.update({dvals[dvals.index('"ID"')+1]:dvals})
	return ddict#returns the newly created dictionary

def dirTree(path):#searches a path for files
	fils = 0
	for root, dirs, files in os.walk(path):
		for f in files:
			if '.wh..wh.aufs' in f:
				pass
			else:	
				print(root+'/'+f)[-50:]
				fils += 1#adds to a counter for each file found
	return fils


def main():
	_=os.system("clear")#cleans up the terminal
	print("*****\nWelcome to Docker Forensics Scripted\n*****\n")
	recovery = False#recovery mode off by default
	sd = 'aufs'#default storage driver
	cmdline = len(sys.argv)
	
	while True:#get path to docker loop
		menu = 'YES'#we are ready to pass to the main menu
		if cmdline == 2:
			hostdir = str(sys.argv[1])
			cmdline = 0
		else:
			hostdir = str(raw_input('Enter the path to the docker host >> ')) or '.'#asks for user input of docker host
	
		if hostdir[0] == '/':
			pass
		else:
			hostdir = hostdir.strip('/')

		if os.path.isfile('%s/image/overlay2/repositories.json' % hostdir):#searches for files based on storage driver, sets appropriately
			sd = 'overlay2'
		elif os.path.isfile('%s/image/aufs/repositories.json' % hostdir):
			sd = 'aufs'
		else:
			print('Incomplete Docker host found at %s' % hostdir)#likely a deleted file recovery
			while True:
				try:
					menu = str(raw_input('\nTo attempt analysis anyways type YES >> '))#asks for user confirmation
					print('')
					break
				except ValueError as e:#when input is invalid
					elog(e)
					print("Error: Not a valid entry, try again\n")
			if menu == 'YES':#if user has typed YES, enter recovery mode to work with an incomplete host
				recovery = True
		
		
		if menu == 'YES':#when ready to enter the menu, display info on storage driver, and path to docker
			_=os.system("clear")
			print('INFO: Docker host is running %s storage driver found at %s' % (sd,hostdir))
			break
		else:
			pass
	print('')

	while True:#menu loop
		print("\n*****\nWelcome to Docker Forensics Scripted\n*****\n\n")
		print('Main Menu\n*****')
		print('(0) Batch mode!')
		print('(1) Search for images')
		print('(2) Search for containers')
		print('(3) Search for data volumes and ALL files within')
		print('(4) Search for events & container logs')
		print('(5) Search for ALL files in ALL container R/W layers')
		print('(6) Search for networks and networked containers')
		print('(7) Perform a raw image scan')
		print('(8) Toggle Storage Driver (AUFS/Overlay2)')
		print('(9) Exit\n*****')
		while True:#get choice input from user
			try:
				menu = int(raw_input('Please make a selection >> '))
				break
			except ValueError as e:#when not an integer
				elog(e)
				print("Error: Not a valid number, try again") 
		_=os.system("clear")
		if menu == 1: #menu choices call the function, passing host and storage driver vals, and display the returned counters
			print ('-----\nImageScan found %d images and %d unique layers!\n-----\n' % imageScan(hostdir,recovery,sd))
		elif menu == 2:
			print('-----\nContainerScan found %d containers and resolved the following information...\n'
				'Image-Links: %d  Runtime: %d  Volume-Links: %d  R/W Layers: %d  Network: %d\n-----\n' % containerScan(hostdir,sd))
		elif menu == 3:
			print('-----\nVolumeScan found %d volumes with %d files!\n-----\n' % volumeScan(hostdir))
		elif menu == 4:
			print('-----\nlogScan found %d logs!\n-----\n' % logScan(hostdir))
		elif menu == 5:
			print('-----\nFileScan found %d files in RW layers!\n-----\n' % fileScan(hostdir,sd))
		elif menu == 6:
			print('-----\nNetworkScan found %d user networks and %d connected containers!\n-----\n' % networkScan(hostdir))
		elif menu == 7:
			print('-----\nRawImageScan found %d images and %d unique layers!\n-----\n' % imageScan(hostdir,True,sd))
		elif menu == 8:#toggles between storage drivers
			if sd == 'aufs': 
				sd = 'overlay2'
			elif sd == 'overlay2':
				sd = 'aufs'
			print('Support for %s enabled!\n' % sd)
		elif menu == 0:#batch mode runs all functions at once, displays collective output
			print('Batch mode on %s...\n' % hostdir)

			printerOFF()#redirects away from stdout and calls each scan function
			(g,h) = imageScan(hostdir,False,sd)
			(i,j) = imageScan(hostdir,True,sd)
			(k,l,m,t,u,v) = containerScan(hostdir,sd)
			(n,o) = volumeScan(hostdir)
			p = logScan(hostdir)
			q = fileScan(hostdir,sd)
			(r,s) = networkScan(hostdir)

			printerON()#redirects back to stdout and displays the results of the operation
			if recovery == False: print('*\nImageScan found %d images and %d unique layers!\n*' % (g,h))
			print('RawImageScan found %d images and %d unique layers!\n*' % (i,j))
			print('ContainerScan found %d containers and resolved the following information...' % k)
			print('Img-Links: %d  Runtime: %d  Vol-Links: %d  R/W Layers: %d  Network: %d\n*' % (l,m,t,u,v))
			print('VolumeScan found %d volumes with %d files!\n*' % (n,o))
			print('logScan found %d logs!\n*' % p)
			print('FileScan found %d files in RW layers!\n*' % q)
			print('NetworkScan found %d user networks and %d connected containers!\n*' % (r,s))

		else:#exits the script
			break
		try:#force a pause after each function returns 
			raw_input('Hit enter to continue...')
		except Exception:
			pass
		_=os.system("clear")
			
main()#call to main()
		
