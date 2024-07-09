
rule Trojan_Win32_Raccrypt_GS_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 32 83 3d ?? ?? ?? ?? 33 } //1
		$a_02_1 = {30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 90 18 46 3b b4 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6c 89 1a 60 c7 44 24 ?? b8 38 69 0e c7 44 24 ?? 7d 00 8d 51 c7 44 24 ?? d2 fb 1a 43 c7 44 24 ?? 2c 31 1b 28 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {36 23 01 00 8b 0d [0-04] 88 04 0f 81 3d [0-04] 66 0c 00 00 } //1
		$a_00_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 } //1
		$a_00_2 = {8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 0a 72 00 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 40 00 00 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 7c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75 } //10
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 kernel32.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 88 c6 05 ?? ?? ?? ?? 79 c6 05 ?? ?? ?? ?? 92 c6 05 ?? ?? ?? ?? 6a 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 85 } //10
		$a_02_1 = {b8 36 23 01 00 01 45 fc 8b [0-05] 03 ?? 08 8b ?? fc 03 ?? 08 8a ?? 88 ?? 8b ?? 5d c2 04 00 } //2
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*2) >=10
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 45 08 8b 45 08 c9 c2 08 00 81 00 eb 34 ef c6 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}