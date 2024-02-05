
rule Trojan_BAT_AgentTesla_ABJR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 05 06 11 05 9a 1f 10 28 90 01 03 0a d2 9c 11 05 17 58 13 05 11 05 06 8e 69 fe 04 13 06 11 06 2d dd 90 00 } //01 00 
		$a_01_1 = {43 00 61 00 72 00 64 00 67 00 61 00 6d 00 65 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 4b 00 } //00 00 
	condition:
		any of ($a_*)
 
}