
rule Trojan_BAT_AgentTesla_JEE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {65 32 61 63 62 34 36 37 2d 37 32 65 65 2d 34 65 39 62 2d 39 35 30 64 2d 65 32 63 66 64 62 38 61 34 38 64 31 } //1 e2acb467-72ee-4e9b-950d-e2cfdb8a48d1
		$a_00_1 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 30 2e 32 2e 34 37 37 39 } //1 Powered by SmartAssembly 8.0.2.4779
		$a_81_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_81_7 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_9 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_81_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}