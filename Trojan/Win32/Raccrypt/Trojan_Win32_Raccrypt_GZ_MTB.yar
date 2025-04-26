
rule Trojan_Win32_Raccrypt_GZ_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 [0-0a] c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 [0-0a] 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GZ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {35 b3 5a 22 c7 45 ?? be a4 bb 7e c7 45 ?? 6a f5 d1 22 c7 45 ?? ce 4d 4a 5f c7 45 ?? 6f e9 1a 32 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GZ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 f1 1a 2b c7 44 24 ?? f9 0b 2b 23 c7 44 24 ?? 54 d6 ab 00 c7 44 24 ?? d1 f0 0d 7b c7 44 24 ?? 68 17 ab 44 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GZ_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {f6 56 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GZ_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 40 00 00 00 [0-0e] c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 63 } //10
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 kernel32.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Raccrypt_GZ_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 [0-0f] 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}