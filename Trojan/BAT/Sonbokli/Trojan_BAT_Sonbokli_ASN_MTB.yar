
rule Trojan_BAT_Sonbokli_ASN_MTB{
	meta:
		description = "Trojan:BAT/Sonbokli.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2c 10 08 7b 02 00 00 04 8e 69 16 fe 02 16 fe 01 2b 01 17 00 13 05 11 05 2d 0c 00 07 16 6f 13 00 00 0a 00 00 2b 0a 00 07 17 6f 13 00 00 0a 00 00 07 } //01 00 
		$a_03_1 = {0a 00 00 06 02 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c de 21 0b 00 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 00 14 0c de 10 06 14 fe 01 0d 09 2d 07 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}