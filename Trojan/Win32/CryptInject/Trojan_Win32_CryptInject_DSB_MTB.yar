
rule Trojan_Win32_CryptInject_DSB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 2b c6 8b 4d 90 01 01 89 01 8b 55 90 01 01 8b 02 05 5c 11 00 00 8b 4d 90 01 01 89 01 8b 55 90 01 01 8b 02 2d 5c 11 00 00 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //1
		$a_03_1 = {8b d2 8b d2 a1 90 01 04 8b d2 8b 0d 90 01 04 8b d2 a3 90 01 04 8b c0 a1 90 01 04 a3 90 01 04 a1 90 01 04 8b d8 a1 90 01 04 33 d9 c7 05 90 01 04 00 00 00 00 01 1d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}