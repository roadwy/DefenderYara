
rule Trojan_BAT_AgentTesla_CYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 02 8e 69 17 da 91 1f 70 61 0c } //01 00 
		$a_01_1 = {09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c } //01 00 
		$a_01_2 = {25 47 02 08 1f 10 5d 91 61 d2 52 } //00 00 
	condition:
		any of ($a_*)
 
}