
rule HackTool_MacOS_MythicAgent_X{
	meta:
		description = "HackTool:MacOS/MythicAgent.X,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 79 74 68 69 63 41 67 65 6e 74 } //1 MythicAgent
		$a_00_1 = {70 6f 73 65 69 64 6f 6e 2f 50 61 79 6c 6f 61 64 } //1 poseidon/Payload
		$a_00_2 = {68 74 74 70 5f 69 6e 69 74 69 61 6c 5f 63 6f 6e 66 69 67 3d } //1 http_initial_config=
		$a_00_3 = {70 72 6f 78 79 5f 62 79 70 61 73 73 3d } //1 proxy_bypass=
		$a_00_4 = {53 65 6e 64 46 69 6c 65 54 6f 4d 79 74 68 69 63 } //1 SendFileToMythic
		$a_00_5 = {73 75 64 6f 5f 70 6f 73 65 69 64 6f 6e } //1 sudo_poseidon
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}