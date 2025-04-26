
rule Trojan_Win32_Zusy_AC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e6 04 2b f1 03 b5 ?? ?? ff ff 52 03 f6 0f af de 03 9d ?? ?? ff ff 51 32 c3 88 85 } //1
		$a_01_1 = {54 0e 46 bf 0e 66 74 53 4b 5c f6 06 67 48 6a 3e 0a 72 70 64 4a 47 66 50 a6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Zusy_AC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d7 e8 8a ff ff ff 85 c0 74 30 8b 75 fc 33 c9 85 f6 74 1e 0f b7 04 4b 33 d2 c7 45 fc 34 00 00 00 f7 75 fc 66 8b 44 55 90 66 89 04 4b 41 3b ce 72 e2 33 c0 66 89 04 1f 40 eb 02 } //2
		$a_01_1 = {57 68 30 22 40 00 53 ff d6 e8 82 f8 ff ff 68 20 32 40 00 53 85 c0 74 76 ff d6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}