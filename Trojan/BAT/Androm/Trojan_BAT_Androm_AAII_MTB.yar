
rule Trojan_BAT_Androm_AAII_MTB{
	meta:
		description = "Trojan:BAT/Androm.AAII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 14 0b 28 90 01 01 00 00 06 0b 07 8e 69 8d 90 01 01 00 00 01 0c 16 0d 38 90 01 01 00 00 00 08 09 07 09 91 06 09 06 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}