
rule Trojan_BAT_SpyNoon_SHVP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SHVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 12 d4 91 13 15 11 07 11 04 95 11 07 11 05 95 58 d2 13 16 11 07 11 16 20 ff 00 00 00 5f 95 d2 13 17 11 15 11 17 61 13 18 11 08 11 12 d4 11 18 20 ff 00 00 00 5f d2 9c 11 18 13 19 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}