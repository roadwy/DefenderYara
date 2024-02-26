
rule Trojan_BAT_AgentTesla_MBJJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 72 2f 00 00 70 28 90 01 01 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4 90 00 } //01 00 
		$a_01_1 = {2f 00 2f 00 71 00 75 00 2e 00 61 00 78 00 2f } //00 00 
	condition:
		any of ($a_*)
 
}