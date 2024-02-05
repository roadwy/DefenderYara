
rule Trojan_BAT_AgentTesla_ABVU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {07 8e 69 17 da 13 18 16 13 19 2b 15 08 11 19 07 11 19 9a 1f 10 28 90 01 01 00 00 0a 9c 11 19 17 d6 13 19 11 19 11 18 31 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}