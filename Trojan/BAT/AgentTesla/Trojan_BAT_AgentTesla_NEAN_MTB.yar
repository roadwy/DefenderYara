
rule Trojan_BAT_AgentTesla_NEAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 22 00 00 0a 72 25 00 00 70 28 07 00 00 06 6f 23 00 00 0a 28 24 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 0b de 17 } //05 00 
		$a_01_1 = {77 00 74 00 72 00 61 00 73 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}