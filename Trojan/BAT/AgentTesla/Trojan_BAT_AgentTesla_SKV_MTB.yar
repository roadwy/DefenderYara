
rule Trojan_BAT_AgentTesla_SKV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {91 13 0d 11 06 09 95 11 06 11 04 95 58 d2 13 0e 11 0e 20 ff 00 00 00 5f d2 13 0f 11 06 11 0f 95 d2 13 10 11 0d 11 10 61 13 11 11 07 } //1
		$a_81_1 = {37 46 4a 45 33 46 34 52 38 46 46 30 31 35 41 47 4f 34 41 35 38 47 } //1 7FJE3F4R8FF015AGO4A58G
		$a_81_2 = {54 69 6d 65 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //1 TimeWindowsFormsApplication.Properties
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SKV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SKV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1f 16 5d 13 07 09 11 04 28 01 00 00 2b 11 05 28 01 00 00 2b 28 02 00 00 2b 11 07 91 13 08 11 06 17 58 08 5d 13 09 07 11 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a 07 11 06 11 0a 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}