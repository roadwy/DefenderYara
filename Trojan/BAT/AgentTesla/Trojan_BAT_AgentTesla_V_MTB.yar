
rule Trojan_BAT_AgentTesla_V_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 15 a2 01 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 04 00 00 00 05 00 00 00 0d } //3
		$a_81_1 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //3 SecurityProtocolType
		$a_81_2 = {57 65 62 52 65 73 70 6f 6e 73 65 } //3 WebResponse
		$a_81_3 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //3 get_ResourceManager
		$a_81_4 = {53 65 72 76 69 63 65 50 6f 69 6e 74 4d 61 6e 61 67 65 72 } //3 ServicePointManager
		$a_81_5 = {39 39 2e 30 2e 34 38 33 32 2e 30 } //3 99.0.4832.0
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_V_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.V!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 46 49 6c 65 49 6e 4d 65 6d 6f 72 79 } //1 RunFIleInMemory
		$a_01_1 = {64 65 63 72 79 70 74 42 79 74 65 73 } //1 decryptBytes
		$a_01_2 = {55 6e 62 6c 6f 63 6b 46 69 6c 65 } //1 UnblockFile
		$a_01_3 = {47 65 74 50 72 6f 63 65 73 73 65 73 00 4b 69 6c 6c } //1
		$a_01_4 = {67 65 74 5f 46 69 6c 65 4e 61 6d 65 00 67 65 74 5f 42 61 73 65 41 64 64 72 65 73 73 } //1 敧彴楆敬慎敭最瑥䉟獡䅥摤敲獳
		$a_01_5 = {52 75 6e 50 65 31 00 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}