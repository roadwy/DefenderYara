
rule Trojan_BAT_SpyNoon_PPF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.PPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 09 8e 69 5d 09 8e 69 58 13 07 11 07 09 8e 69 5d 13 08 09 11 08 91 13 09 11 06 17 58 08 5d 13 0a 11 0a 08 58 13 0b 11 0b 08 5d 13 0c 11 0c 08 5d 08 58 13 0d 11 0d 08 5d 13 0e 07 11 0e 91 13 0f 11 06 08 5d 08 58 13 10 11 10 08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13 11 13 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}