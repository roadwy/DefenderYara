
rule Trojan_BAT_SpyNoon_FIFA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.FIFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 0c 02 00 0b 38 13 00 00 00 00 06 07 20 00 01 00 00 28 90 01 03 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 3a df ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}