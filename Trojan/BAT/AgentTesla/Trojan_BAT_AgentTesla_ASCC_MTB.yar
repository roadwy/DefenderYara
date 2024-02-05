
rule Trojan_BAT_AgentTesla_ASCC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0d 16 13 06 2b 1f 00 09 11 06 08 11 06 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 9c 00 11 06 17 58 13 06 11 06 09 8e 69 fe 04 13 07 11 07 2d d4 90 00 } //01 00 
		$a_81_1 = {47 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}