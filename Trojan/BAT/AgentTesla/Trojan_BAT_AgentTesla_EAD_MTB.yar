
rule Trojan_BAT_AgentTesla_EAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0c 16 13 06 2b 17 00 08 11 06 07 11 06 9a 1f 10 28 90 01 01 00 00 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dc 90 00 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_2 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}