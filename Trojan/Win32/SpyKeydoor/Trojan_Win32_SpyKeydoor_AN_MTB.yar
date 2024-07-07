
rule Trojan_Win32_SpyKeydoor_AN_MTB{
	meta:
		description = "Trojan:Win32/SpyKeydoor.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 37 32 da 32 d8 32 d9 88 1e 8a d8 32 d9 22 da 8a d0 22 d1 32 da 8b 54 24 10 8a cb 8d 1c d5 00 00 00 00 33 da 81 e3 f8 07 00 00 c1 e3 14 c1 ea 08 0b d3 8d 1c 00 33 d8 c1 e3 04 33 d8 8b e8 83 e3 80 c1 e5 07 33 dd c1 e3 11 c1 e8 08 0b c3 46 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}