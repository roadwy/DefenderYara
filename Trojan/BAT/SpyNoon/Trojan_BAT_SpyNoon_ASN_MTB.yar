
rule Trojan_BAT_SpyNoon_ASN_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 5d 16 0d 2b 18 7e 01 00 00 04 72 b7 00 00 70 28 ?? ?? ?? 0a 80 01 00 00 04 09 17 58 0d 09 03 32 e4 } //2
		$a_01_1 = {76 00 74 00 2d 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 vt-client.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}