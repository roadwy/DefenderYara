
rule Trojan_BAT_SpyNoon_SZDF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SZDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 15 11 15 1f 7b 61 20 ff 00 00 00 5f 13 16 11 16 20 c8 01 00 00 58 20 00 01 00 00 5e 13 16 11 16 16 fe 01 13 17 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}