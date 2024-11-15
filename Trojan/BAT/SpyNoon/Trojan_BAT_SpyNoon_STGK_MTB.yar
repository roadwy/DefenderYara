
rule Trojan_BAT_SpyNoon_STGK_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.STGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 16 fe 02 13 05 11 05 2c 40 00 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 fe 02 13 06 11 06 2c 0e 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 18 fe 02 13 07 11 07 2c 0e 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 03 6f ?? ?? ?? 0a 04 fe 04 16 fe 01 13 08 11 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}