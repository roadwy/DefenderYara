
rule Trojan_BAT_AgentTesla_EQL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 06 02 06 91 11 05 18 d6 18 da 61 11 04 07 19 d6 19 da 91 61 } //01 00 
		$a_03_1 = {07 02 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}