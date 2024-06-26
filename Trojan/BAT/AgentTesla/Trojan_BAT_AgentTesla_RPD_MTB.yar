
rule Trojan_BAT_AgentTesla_RPD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 00 2e 00 35 00 38 00 2e 00 31 00 34 00 39 00 2e 00 32 00 2f 00 90 02 40 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 39 00 30 00 2e 00 31 00 32 00 33 00 2e 00 34 00 34 00 2e 00 31 00 33 00 38 00 2f 00 39 00 34 00 33 00 } //01 00  190.123.44.138/943
		$a_01_1 = {41 00 73 00 73 00 65 00 74 00 73 00 } //01 00  Assets
		$a_01_2 = {52 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 77 00 61 00 76 00 } //01 00  Rocket.wav
		$a_01_3 = {43 00 69 00 72 00 63 00 6c 00 65 00 2e 00 70 00 6e 00 67 00 } //01 00  Circle.png
		$a_01_4 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //01 00  CreateInstance
		$a_01_5 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //01 00  GetExportedTypes
		$a_01_6 = {53 00 70 00 61 00 63 00 65 00 2e 00 6a 00 70 00 67 00 } //01 00  Space.jpg
		$a_01_7 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  HttpWebResponse
		$a_01_8 = {47 65 74 52 61 6e 64 6f 6d 4e 75 6d 62 65 72 } //01 00  GetRandomNumber
		$a_01_9 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}