
rule Trojan_Win32_Raccrypt_GE_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 14 30 81 3d ?? ?? ?? ?? 03 02 00 00 } //1
		$a_02_1 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 90 18 46 3b f7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec b8 90 0a 6e 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GE_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {32 00 2e 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 90 0a 78 00 65 00 00 00 ?? 6b 00 00 00 [0-14] 33 00 00 00 [0-0a] 72 00 00 00 ?? 6c 00 00 00 [0-02] c7 05 } //1
		$a_02_1 = {50 b9 6c 00 00 00 ba 2e 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GE_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 84 32 36 23 01 00 88 04 31 81 c4 ?? ?? 00 00 c3 } //10
		$a_02_1 = {c1 ea 05 03 d5 [0-05] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 } //10
		$a_02_2 = {51 c7 04 24 02 00 00 00 8b 44 24 ?? ?? 01 04 24 83 2c 24 ?? 8b 04 24 31 01 59 c2 } //1
		$a_02_3 = {81 ec 00 01 00 00 c7 84 24 ?? ?? ?? ?? 57 78 d1 51 c7 84 24 ?? ?? ?? ?? 0b 4c 1b 7e c7 44 24 ?? dd 0b fa 64 c7 44 24 ?? cf 72 b2 3d c7 84 24 ?? ?? ?? ?? e9 0e 74 64 c7 44 24 ?? a9 53 5d 16 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=21
 
}