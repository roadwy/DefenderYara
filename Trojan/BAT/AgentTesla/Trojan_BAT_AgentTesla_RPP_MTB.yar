
rule Trojan_BAT_AgentTesla_RPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0a 00 00 "
		
	strings :
		$a_03_0 = {39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 31 00 34 00 32 00 2f 00 90 02 30 2e 00 6a 00 70 00 67 00 90 00 } //10
		$a_01_1 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_8 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_9 = {41 64 64 53 65 63 6f 6e 64 73 } //1 AddSeconds
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=15
 
}
rule Trojan_BAT_AgentTesla_RPP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {62 00 6c 00 75 00 65 00 63 00 6f 00 76 00 65 00 72 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 90 02 10 2e 00 74 00 78 00 74 00 90 00 } //1
		$a_01_1 = {64 00 6c 00 6c 00 2e 00 74 00 78 00 74 00 } //1 dll.txt
		$a_01_2 = {52 00 55 00 4e 00 52 00 55 00 4e 00 52 00 55 00 4e 00 52 00 55 00 4e 00 52 00 55 00 4e 00 } //1 RUNRUNRUNRUNRUN
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_01_6 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_7 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_8 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule Trojan_BAT_AgentTesla_RPP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2c 03 17 2b 03 16 2b 00 2d 03 26 2b 07 28 1a 00 00 0a 2b 00 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}