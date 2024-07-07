
rule Trojan_BAT_SpyNoon_DWOF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.DWOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7b 60 00 00 04 6f 90 01 03 0a 00 28 90 01 03 06 0a 28 90 01 03 0a 72 62 01 00 70 6f 90 01 03 0a 1e 8d 42 00 00 01 17 73 50 00 00 0a 0b 73 51 00 00 0a 0c 08 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 08 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 08 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 0d 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}