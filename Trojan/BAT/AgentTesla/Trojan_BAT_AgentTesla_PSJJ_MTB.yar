
rule Trojan_BAT_AgentTesla_PSJJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 72 df 04 00 70 6f 90 01 03 0a 74 90 01 03 1b 0c 08 8e 69 8d 7f 00 00 01 0d 16 13 05 2b 18 09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}