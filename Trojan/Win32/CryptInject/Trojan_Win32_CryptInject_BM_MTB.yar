
rule Trojan_Win32_CryptInject_BM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {be 88 06 00 00 57 85 f6 74 ?? 31 c0 33 03 83 eb fc 83 e8 33 c1 c8 08 29 d0 83 e8 01 8d 10 c1 c2 09 d1 ca 6a 00 8f 07 01 47 00 83 c7 04 83 ee 04 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_BM_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 94 2a ?? ?? ?? ?? 8a 19 32 da 83 c0 05 3d ?? ?? ?? ?? 88 19 0f 8c ?? ?? ff ff [0-4f] 68 00 30 00 00 [0-2f] 6a 00 ff } //1
		$a_03_1 = {75 0e 8a 85 ?? ?? ?? ?? 8b 4d 04 34 ?? 88 41 } //1
		$a_03_2 = {75 0f 8a 8d ?? ?? ?? ?? 8b 55 04 80 f1 ?? 88 4a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}