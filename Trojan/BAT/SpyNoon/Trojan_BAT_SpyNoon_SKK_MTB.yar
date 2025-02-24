
rule Trojan_BAT_SpyNoon_SKK_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 1b 11 18 11 0b 91 13 29 11 18 11 0b 11 29 11 22 61 19 11 1d 58 61 11 2f 61 d2 9c } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}