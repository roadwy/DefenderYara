
rule Trojan_BAT_AgentTesla_LBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 33 00 09 11 04 11 05 6f 90 01 03 0a 13 08 09 11 04 11 05 6f 90 01 03 0a 13 09 11 09 28 90 01 03 0a 13 0a 08 07 11 0a 28 90 01 03 0a 9c 00 11 05 17 58 13 05 11 05 09 6f 90 01 03 0a fe 04 13 0b 11 0b 2d 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}