
rule Trojan_BAT_AgentTesla_LXEA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LXEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 07 09 20 00 c4 00 00 28 90 01 03 06 0b 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d df 90 00 } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 } //1 WinFormProjects
		$a_01_4 = {55 00 44 00 37 00 45 00 37 00 38 00 44 00 4f 00 36 00 50 00 59 00 38 00 48 00 37 00 53 00 58 00 5a 00 52 00 35 00 38 00 53 00 5a 00 } //1 UD7E78DO6PY8H7SXZR58SZ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}