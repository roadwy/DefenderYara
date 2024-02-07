
rule Trojan_BAT_AgentTesla_MBFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 03 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 2a 90 00 } //01 00 
		$a_01_1 = {35 65 38 62 35 62 39 36 34 31 39 30 } //00 00  5e8b5b964190
	condition:
		any of ($a_*)
 
}