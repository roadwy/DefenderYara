
rule Trojan_BAT_SpyNoon_ASN_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 5d 16 0d 2b 18 7e 01 00 00 04 72 b7 00 00 70 28 ?? ?? ?? 0a 80 01 00 00 04 09 17 58 0d 09 03 32 e4 } //2
		$a_01_1 = {76 00 74 00 2d 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 vt-client.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_SpyNoon_ASN_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 3d 17 13 08 16 13 09 2b 17 06 09 11 09 58 91 07 11 09 91 2e 05 16 13 08 2b 0d 11 09 17 58 13 09 11 09 07 8e 69 32 e2 11 08 2c 0f 08 09 6f ?? 00 00 0a 09 07 8e 69 58 0d 2b 04 09 17 58 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}