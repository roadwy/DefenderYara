
rule Trojan_BAT_AgentTesla_FLB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 45 30 44 34 43 44 38 56 38 47 37 34 34 34 34 35 39 38 4b 37 38 } //01 00  BE0D4CD8V8G74444598K78
		$a_01_1 = {00 67 65 74 5f 50 61 72 61 6d 58 47 72 6f 75 70 00 } //01 00 
		$a_01_2 = {00 67 65 74 5f 50 61 72 61 6d 58 41 72 72 61 79 00 } //01 00 
		$a_01_3 = {00 46 69 6c 65 5f 31 00 } //01 00  䘀汩彥1
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {00 44 61 74 61 5f 31 00 } //00 00  䐀瑡彡1
	condition:
		any of ($a_*)
 
}