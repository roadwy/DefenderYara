
rule Trojan_BAT_SpyNoon_TTUF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.TTUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 16 74 00 00 0c 2b 16 } //1 ᘠtఀᘫ
		$a_01_1 = {07 08 28 06 01 00 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}