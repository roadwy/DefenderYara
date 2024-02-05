
rule Trojan_BAT_Heracles_MKV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 24 73 a0 00 00 0a 13 06 2b 13 28 a2 00 00 0a 11 12 16 11 12 8e 69 6f a3 00 00 0a 13 06 11 0b 20 63 62 35 fb 06 59 07 61 11 0b 19 5f 58 1b 62 58 13 0b 11 0b } //00 00 
	condition:
		any of ($a_*)
 
}