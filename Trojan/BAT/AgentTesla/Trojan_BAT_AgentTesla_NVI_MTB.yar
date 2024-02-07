
rule Trojan_BAT_AgentTesla_NVI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 } //01 00 
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 00 0f 43 00 6f 00 6e 00 76 00 65 00 72 00 74 } //01 00 
		$a_01_2 = {11 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 00 11 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 } //01 00 
		$a_81_3 = {73 66 64 61 73 } //01 00  sfdas
		$a_81_4 = {5f 64 64 64 } //01 00  _ddd
		$a_81_5 = {5f 69 69 69 69 69 69 69 69 } //01 00  _iiiiiiii
		$a_81_6 = {73 61 64 66 61 73 66 } //00 00  sadfasf
	condition:
		any of ($a_*)
 
}