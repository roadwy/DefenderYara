
rule Trojan_BAT_AgentTesla_PSOG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 7b 00 00 06 28 90 01 03 06 28 90 01 03 06 20 a7 01 00 00 20 9d 01 00 00 28 90 01 03 2b 74 0c 00 00 02 28 90 01 03 06 6f 90 01 03 06 80 05 00 00 04 2a d0 8c 00 00 06 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}