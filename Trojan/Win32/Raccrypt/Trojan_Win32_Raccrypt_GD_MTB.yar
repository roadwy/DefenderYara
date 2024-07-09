
rule Trojan_Win32_Raccrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 f1 1a 2b c7 44 24 ?? f9 0b 2b 23 89 4c 24 ?? c7 44 24 ?? d1 f0 0d 7b c7 44 24 ?? 68 17 ab 44 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 8b [0-0f] c1 ?? 05 8d [0-0f] 90 17 02 01 01 31 33 [0-0f] 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 84 32 36 23 01 00 88 04 31 81 c4 ?? ?? 00 00 c3 } //10
		$a_02_1 = {c1 ea 05 03 d5 c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 74 24 ?? 8d 44 24 ?? e8 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 90 0a 32 00 c1 ?? 04 03 [0-0f] c1 ?? 05 03 [0-1e] 90 17 02 01 01 31 33 [0-14] c7 05 } //1
		$a_02_1 = {b4 21 e1 c5 90 0a 32 00 c1 ?? 05 03 [0-0f] c1 ?? 04 03 [0-1e] 90 17 02 01 01 31 33 [0-14] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 ff 35 [0-14] c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f [0-07] c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}