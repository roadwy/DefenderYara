
rule Trojan_BAT_AgentTesla_EREGA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EREGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {d0 24 00 00 01 28 90 01 03 0a 72 a3 04 00 70 20 00 01 00 00 14 14 17 8d 10 00 00 01 25 16 02 a2 28 90 01 03 0a 74 24 00 00 01 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}