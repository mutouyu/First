import sys
		# config.password = PassWord
		# if(len(args_) < 3):
		# 	print("Usage:run.bat <ip> <username> <password>")
		# 	return

		config = cs_get_stat()
		config.ip = args_[0]
		config.username = args_[1]
		config.password = args_[2]
		client = None

		try:
			client = nitro_service(config.ip,"http")
			client.set_credential(config.username,config.password)
			client.timeout = 500
			print("Input an parament:")
			print("  name  <-------> Name of the content switching virtual server")
			print("  state <-------> The state of the server")
			print("  ip    <-------> The IP address on which the service is running")
			print("  port  <-------> The port on which the service is running")
			print("  hits  <-------> The total vserver hits")
			print("  all   <-------> The whole information of the content switching virtual server")
			parament1 = raw_input("Your input is:")
			print("****************************************")
			config.run_state(client,parament1)
			print("****************************************")
			#print("Input the csvserver name:")
			parament2 = raw_input("Input the csvserver name:")
			print("<<------------------------------------->>")
			config.run_csvserver_name(client,parament2)
			
			#print("sessionID=" + client.sessionid)			#get sessionid, used for login
			# if client.isLogin():
			# 	config.run_sample2(client)
			client.logout()

		except nitro_exception as e:
			print("Exception:: errorcode=" +str(e.errorcode)+",message+" + e.message)
		except Exception as e:
			print("Exception::message=" +str(e.args))
		return


	def get_csvserver_stats(self,client,parament1):
		try:
			result = csvserver_stats.get(client)
			if result:
				if parament1 == "name":
					for j in range(0,len(result)):
						print("	Name :" + result[j].name)
						# print("	IP:" + result[j].primaryipaddress + ":" + str(result[j].primaryport))
						# print("	State:" + result[j].state + "	Type" + result[j].type)
						# print("	Total hits:" + result[j].tothits + "	Hits rates:" + str(result[j].hitsrate))
						print
				elif parament1 == "state":
					for j in range(0,len(result)):
						print("	"+result[j].name + " :State :" + result[j].state)
						print
				elif parament1 == "port":
					for j in range(0,len(result)):
						print("	"+result[j].name + " :Port :" + str(result[j].primaryport))
						print
				elif parament1 == "ip":
					for j in range(0,len(result)):
						print("	"+result[j].name + " :IP :" + str(result[j].primaryipaddress))
						print
				elif parament1 == "hits":
					for j in range(0,len(result)):
						print("	"+result[j].name + " :Total hits:" + result[j].tothits)
						print
				elif parament1 == "all":
					for j in range(0,len(result)):
						print("	Name : " + result[j].name)
						print("	IP:" + result[j].primaryipaddress + ":" + str(result[j].primaryport))
						print("	State:" + result[j].state + "	Type: " + result[j].type)
						print("	Total hits:" + result[j].tothits + "	Hits rates:" + str(result[j].hitsrate))		
						print("	Established State : " + result[j].establishedconn)
						print("	Total requests :" + result[j].totalrequests)
						print("	Request rates: " + str(result[j].requestsrate))
						print("	Request bytes:" + str(result[j].totalrequestbytes))
						print("	Total responses :" + result[j].totalresponses)
						print( "Responses rate: " + str(result[j].responsesrate))
						print("	Current server :" + str(result[j].cursrvrconnections))
						print
			#print("****************************************")
		except nitro_exception as e :
			print("Exception:: errorcode=" + str(e.errorcode) + ", message=" + e.message)
		except Exception as e :
			print("Exception:: get_csvserver_stats:: message=" + str(e.args))

	def get_cspolicy(self,client,parament2):
		try:
			result1 = cspolicy.get(client)
			if result1:
				for i in range(0,len(result)):
					print("Name of Policy:" + result[i].policyname)
					print
					print("Policy URL:" + result[i].url)
					print
					# print("The Rule is :" + result[i].rule)
					# print
					print("This policy hit is :" + result[i].hits)
					print
					print("****************************************")
					
		except nitro_exception as e :
			print("Exception:: errorcode=" + str(e.errorcode) + ", message=" + e.message)
		except Exception as e :
			print("Exception:: get_cspolicy:: message=" + str(e.args))


	def get_csvserver(self,client,parament2):
		try:
			result_csvserver_state = csvserver_stats.get(client)
			result_cspolicy = cspolicy.get(client)
			result_lbvserver_state = lbvserver_stats.get(client)
			if result_csvserver_state:
				flag = False
				for i in range(0,len(result_csvserver_state)):
					#if parament2 == res
					if parament2 == result_csvserver_state[i].name:
						flag = True
						policy_count = csvserver_cspolicy_binding.count(client,result_csvserver_state[i].name)
						policy_name = csvserver_cspolicy_binding.get(client,result_csvserver_state[i].name)
						print("	Name :" + result_csvserver_state[i].name)
						print("	IP: " + result_csvserver_state[i].primaryipaddress + ":" + str(result_csvserver_state[i].primaryport))
						print("	State:" + result_csvserver_state[i].state + "	Type: " + result_csvserver_state[i].type)
						print("	Total hits:" + result_csvserver_state[i].tothits + "	Hits rates:" + str(result_csvserver_state[i].hitsrate))
						#print("	Established State : " + result[j].establishedconn)
						print("	Total requests :" + result_csvserver_state[i].totalrequests)
						print("	Total responses :" + result_csvserver_state[i].totalresponses)
						print("	Current server :" + str(result_csvserver_state[i].cursrvrconnections))
						print
						#print("<-------------------------------------->")
						
						for k in range(0,policy_count):
							for j in range(0,len(result_cspolicy)):
								global URL
								if result_cspolicy[j].policyname == policy_name[k].policyname :
									URL = result_cspolicy[j].url
									#print("url:" + URL)
							print("	Policy:")
							print("	|--- Name: " + policy_name[k].policyname)
							print("	|--- Hits: " + policy_name[k].hits)
							print("	|--- URL: " + URL)
							print("	|--- Priority: " + policy_name[k].priority)
							print("	|--- Target LB: " + policy_name[k].targetlbvserver)
							print

						for k in range(0,policy_count):
							# for j in range(0,len(result_cspolicy)):
							print
							print("	Policy  "+ policy_name[k].policyname + " Target LBvserver:")
					
							global lbvserver_name 
							lbvserver_name = policy_name[k].targetlbvserver
						
							for p in range(0,len(result_lbvserver_state)):
								if lbvserver_name == result_lbvserver_state[p].name :
									# print("	LBvserver:")
									print("	|--- Name: " + result_lbvserver_state[p].name)
									print("	|--- IP: " + result_lbvserver_state[p].primaryipaddress)
									print("	|--- Port:" + str(result_lbvserver_state[p].primaryport))
									print("	|--- State: " + result_lbvserver_state[p].state)
									print("	|--- Type: " + result_lbvserver_state[p].type)
									print("	|--- Request bytes:" + result_lbvserver_state[p].totalresponsebytes)
									print("	|--- Total packets sent:" + result_lbvserver_state[p].totalpktssent)
									print("	|--- Health of the vserver:" + result_lbvserver_state[p].vslbhealth)
									print("	|--- Number of client connections in ESTABLISHED state:" + result_lbvserver_state[p].establishedconn)
									result_lbv_service_binding = lbvserver_service_binding.get(client,result_lbvserver_state[p].name)
									for kk in range(0,len(result_lbv_service_binding)):
										print("	|--- Service : ")
										print("		>--- Service Name : " + result_lbv_service_binding[kk].servicename)
										print("		>--- Service IP :" + result_lbv_service_binding[kk].ipv46)
										print("		>--- Service State: " + result_lbv_service_binding[kk].curstate)

							#print("<<------------------------------------>>")
					elif (i == len(result_csvserver_state)-1)&(flag == False):
						#print(isinstance(i,int))
					#elif i == len(result_csvserver)-1:
						print("There is no such csvserver name or policy, Exit!")




				# policy_count = csvserver_cspolicy_binding.count(client,result[i].name)
				# 	print("policy count:" + str(policy_count))
				# 	policy_name = csvserver_cspolicy_binding.get(client,result[i].name)
				# 	for j in range(0,policy_count):
				# 		print("Policy name :" + policy_name[j].policyname)
				# for i in range(0,len(result)):
				# 	print("Name of csvserver:" + result[i].name)
				# 	print
				# 	print("Target Load Balance Virtual Server:" + result[i].lbvserver)
				# 	print
				# 	print("The State of csvserver:" + result[i].curstate)
				# 	print
				# 	print("Down State Flush" + result[i].downstateflush)
				# 	print
				# 	print("****************************************")
			print("****************************************")
		except nitro_exception as e :
			print("Exception:: errorcode=" + str(e.errorcode) + ", message=" + e.message)
		except Exception as e :
			print("Exception:: get_csvserver:: message=" + str(e.args))




	def run_state(self, client, parament1):
		self.get_csvserver_stats(client,parament1);

		# self.get_csvserver_stats(client);
		# self.get_cspolicy(client);
		# self.get_csvserver(client);
			
		# self.get_lbvserver(client);


	def run_csvserver_name(self,client,parament2):
		self.get_csvserver(client,parament2);


if  __name__ == '__main__':
	try:
		array = [raw_input("Input ip address:")," ", " "]
		array[1] = raw_input("Input your username:")
		array[2] = getpass.getpass("Input your password:")
	
		if len(array) != 3:
	 		sys.exit()
		else:
			#get_state().main(get_state(),array)
			cs_get_stat().csvserver_method(array)
	except SystemExit:
	 	print("Exception::Usage: Sample.py <directory> <nsip> <username> <password>")





