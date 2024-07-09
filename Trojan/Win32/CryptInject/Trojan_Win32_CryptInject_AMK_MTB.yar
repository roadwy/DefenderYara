
rule Trojan_Win32_CryptInject_AMK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {0b c1 8b 4d f8 0f b6 4c 0d ?? 8b 55 f8 2b 55 ?? 0f b6 54 15 ?? 0f b7 54 55 ?? 23 ca 2b c1 8b 4d f8 0f b6 4c 0d ?? 66 89 44 4d } //10
		$a_02_1 = {33 c0 40 c1 e0 00 0f b6 44 05 ?? 83 c8 ?? 33 c9 41 c1 e1 00 0f b6 4c 0d ?? 83 e1 ?? 2b c1 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}