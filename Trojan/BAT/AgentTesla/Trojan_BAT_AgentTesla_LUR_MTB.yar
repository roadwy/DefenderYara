
rule Trojan_BAT_AgentTesla_LUR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d d5 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}