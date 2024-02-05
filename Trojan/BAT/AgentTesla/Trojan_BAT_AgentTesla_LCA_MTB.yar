
rule Trojan_BAT_AgentTesla_LCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 05 6f 90 01 03 0a 26 09 11 04 11 05 6f 90 01 03 0a 28 90 01 03 0a 13 08 08 07 11 08 d2 9c 11 05 17 58 13 05 11 05 09 6f 90 01 03 0a 32 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_3 = {54 6f 57 69 6e 33 32 } //00 00 
	condition:
		any of ($a_*)
 
}