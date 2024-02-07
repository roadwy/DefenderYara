
rule Trojan_BAT_AgentTesla_CZD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 9a 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 13 05 07 11 05 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 11 04 17 d6 13 04 90 00 } //01 00 
		$a_01_1 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //01 00  gnirtS46esaBmorF
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}