
rule Trojan_BAT_AgentTesla_SW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 cc 00 00 5d 13 09 11 08 20 00 cc 00 00 5d 13 0a 07 11 09 91 13 0b 1f 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_SW_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 5c 00 00 5d 07 09 20 00 5c 00 00 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 07 09 17 58 20 00 5c 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d b3 90 00 } //1
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_4 = {4c 00 75 00 63 00 69 00 64 00 69 00 74 00 79 00 2e 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 } //1 Lucidity.WinForms
		$a_01_5 = {37 00 4b 00 38 00 47 00 38 00 45 00 48 00 35 00 34 00 4e 00 35 00 35 00 37 00 38 00 55 00 5a 00 32 00 39 00 5a 00 37 00 35 00 34 00 } //1 7K8G8EH54N5578UZ29Z754
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}