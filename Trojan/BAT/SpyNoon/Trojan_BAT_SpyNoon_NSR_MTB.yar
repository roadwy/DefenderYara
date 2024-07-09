
rule Trojan_BAT_SpyNoon_NSR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.NSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 02 28 07 00 00 0a 28 ?? 00 00 06 00 09 28 ?? 00 00 06 00 07 28 ?? 00 00 06 13 04 de 2c } //5
		$a_01_1 = {4b 00 6f 00 73 00 74 00 65 00 6e 00 6d 00 69 00 6e 00 69 00 6d 00 61 00 6c 00 46 00 6c 00 75 00 73 00 73 00 } //1 KostenminimalFluss
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}