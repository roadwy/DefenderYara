
rule Trojan_BAT_LgoogLoader_MBT_MTB{
	meta:
		description = "Trojan:BAT/LgoogLoader.MBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 7e 90 01 03 04 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 02 28 90 01 03 0a 0c 07 08 16 08 8e 69 6f 90 01 03 0a 0d 09 13 04 de 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}