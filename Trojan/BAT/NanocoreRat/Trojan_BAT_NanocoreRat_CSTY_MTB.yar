
rule Trojan_BAT_NanocoreRat_CSTY_MTB{
	meta:
		description = "Trojan:BAT/NanocoreRat.CSTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? ?? 03 08 18 58 17 59 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 19 58 18 59 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 1a 2d 38 26 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}