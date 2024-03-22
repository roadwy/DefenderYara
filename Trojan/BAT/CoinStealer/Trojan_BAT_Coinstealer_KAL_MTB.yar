
rule Trojan_BAT_Coinstealer_KAL_MTB{
	meta:
		description = "Trojan:BAT/Coinstealer.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2c 02 de 29 06 28 90 01 01 00 00 06 0b 12 01 28 90 01 01 00 00 0a 2d 02 de 17 07 06 28 90 01 01 00 00 06 de 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}