
rule Trojan_BAT_AgentTesla_EQK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 03 04 20 90 01 04 5d 91 02 04 1f 16 5d 90 01 05 61 90 01 05 03 04 17 58 20 90 01 04 5d 91 90 01 05 59 20 00 01 00 00 58 20 00 01 00 00 90 09 07 00 03 04 20 90 00 } //01 00 
		$a_03_1 = {5d 07 09 20 90 01 04 5d 91 08 09 1f 16 5d 90 01 05 61 90 01 05 07 09 17 58 20 90 01 04 5d 91 90 01 05 59 20 00 01 00 00 58 20 00 01 00 00 90 09 07 00 07 09 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}