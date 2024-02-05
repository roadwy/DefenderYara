
rule Trojan_BAT_AgentTesla_ESX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 06 17 da 17 d6 02 11 06 91 08 1f 0a d6 1f 0a da 61 07 11 07 91 61 b4 9c 11 07 03 } //01 00 
		$a_03_1 = {07 02 09 28 90 01 03 06 1f 10 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 0d 09 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}