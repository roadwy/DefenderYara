
rule Trojan_Win32_CryptInject_BD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 e6 04 03 f2 33 d2 3d df 03 00 00 0f 44 ca 8b d7 c1 ea 05 03 95 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 cf 33 d1 33 d6 2b da 8b fb c1 e7 04 3d 93 04 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_BD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b ce 49 8b c1 49 ff c3 48 f7 e6 48 8b c6 48 ff c6 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 ?? 48 [0-0a] 48 2b c1 0f b6 44 [0-04] 41 30 43 ?? 49 ff c8 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}