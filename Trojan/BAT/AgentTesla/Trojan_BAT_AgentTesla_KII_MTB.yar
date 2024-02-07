
rule Trojan_BAT_AgentTesla_KII_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 13 06 07 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d ba 90 00 } //01 00 
		$a_01_1 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //00 00  gnirtS46esaBmorF
	condition:
		any of ($a_*)
 
}