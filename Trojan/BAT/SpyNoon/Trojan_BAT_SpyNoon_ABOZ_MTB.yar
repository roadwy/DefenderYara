
rule Trojan_BAT_SpyNoon_ABOZ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ABOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 28 ?? ?? ?? 06 25 26 20 ?? ?? ?? 00 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 13 05 09 8e 69 8d ?? ?? ?? 01 13 06 11 05 11 06 20 ?? ?? ?? 00 28 ?? ?? ?? 06 11 06 8e 69 28 ?? ?? ?? 06 25 26 26 02 11 06 28 ?? ?? ?? 06 de 35 } //4
		$a_01_1 = {5f 00 30 00 30 00 37 00 53 00 74 00 75 00 62 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 _007Stub.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}