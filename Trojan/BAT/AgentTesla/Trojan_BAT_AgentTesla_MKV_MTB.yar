
rule Trojan_BAT_AgentTesla_MKV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 08 17 8d 90 01 03 01 25 16 11 04 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 1f 10 28 90 01 03 0a 86 6f 90 01 03 0a 00 11 04 17 d6 13 04 00 11 04 8c 90 01 03 01 08 14 72 90 01 03 70 16 8d 90 01 03 01 14 14 14 28 90 01 03 0a 16 28 90 01 03 0a 13 06 11 06 2d a6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}