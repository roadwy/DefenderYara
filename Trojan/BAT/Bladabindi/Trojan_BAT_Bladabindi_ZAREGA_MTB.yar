
rule Trojan_BAT_Bladabindi_ZAREGA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ZAREGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 20 00 01 00 00 6f 90 01 03 0a 11 06 17 6f 90 01 03 0a 11 06 0c 03 2d 11 08 07 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 2b 0f 08 07 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 0d 73 31 00 00 0a 13 04 11 04 09 17 73 32 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}