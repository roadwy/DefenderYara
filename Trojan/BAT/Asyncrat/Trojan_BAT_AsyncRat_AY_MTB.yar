
rule Trojan_BAT_AsyncRat_AY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 30 08 09 a3 4b 00 00 01 13 04 28 90 01 03 06 11 04 07 6f 90 01 03 0a 28 90 01 03 06 6f 90 01 03 0a 2c 05 dd c9 00 00 00 de 03 26 de 00 09 17 58 0d 09 08 8e 69 32 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}