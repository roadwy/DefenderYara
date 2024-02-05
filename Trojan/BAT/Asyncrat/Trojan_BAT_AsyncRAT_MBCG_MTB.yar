
rule Trojan_BAT_AsyncRAT_MBCG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 09 11 09 28 90 01 01 00 00 0a 72 e0 08 00 70 16 28 90 01 01 00 00 0a 16 fe 01 13 0a 11 0a 2c 04 09 17 d6 0d 11 08 17 d6 13 08 11 08 11 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}