
rule Trojan_BAT_AgentTesla_DVP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 26 00 08 09 11 04 28 90 01 03 06 13 07 11 07 28 90 01 03 0a 13 08 07 11 08 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 2d cf 90 00 } //01 00 
		$a_81_1 = {54 6f 57 69 6e 33 32 } //01 00 
		$a_81_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}