
rule Trojan_BAT_AgentTesla_LNG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 44 6f 76 4c 7a 67 79 4c 6a 45 30 4e 69 34 30 4f 53 34 78 4f 54 63 76 } //1 aHR0cDovLzgyLjE0Ni40OS4xOTcv
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_5 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_6 = {47 65 74 50 61 74 68 52 6f 6f 74 } //1 GetPathRoot
		$a_01_7 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}