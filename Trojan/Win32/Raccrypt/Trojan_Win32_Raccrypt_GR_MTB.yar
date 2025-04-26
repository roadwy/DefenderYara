
rule Trojan_Win32_Raccrypt_GR_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 [0-05] e8 ?? ?? ?? ?? 8b [0-03] 29 [0-05] 81 [0-02] 47 86 c8 61 ff [0-05] 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 04 [0-1e] c1 ?? 05 03 [0-0f] 90 17 02 01 01 31 33 } //1
		$a_02_1 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 05 03 [0-1e] c1 ?? 04 [0-0f] 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 02 88 01 8b e5 5d c2 } //1
		$a_02_1 = {d3 ea 89 55 ?? 8b 45 ?? 50 8d 4d ?? 51 e8 [0-04] 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 50 8d 4d ?? 51 e8 [0-04] 8b 55 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}
rule Trojan_Win32_Raccrypt_GR_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 56 8b f0 90 18 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 81 00 a4 36 ef c6 c3 } //10
		$a_00_1 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 81 00 a4 36 ef c6 c3 } //5
		$a_02_2 = {25 bb 52 c0 5d 8b [0-02] 8b [0-04] c1 ?? 04 03 [0-06] 33 [0-08] c1 [0-01] 05 03 } //5
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5) >=10
 
}
rule Trojan_Win32_Raccrypt_GR_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6c 00 6c 00 [0-06] ff 15 90 0a 46 00 57 66 [0-06] c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 } //1
		$a_02_1 = {6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 65 00 72 00 [0-0d] ff 15 90 0a 46 00 6c 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GR_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 04 03 [0-1e] c1 ?? 05 03 90 0a 0f 00 90 17 02 01 01 31 33 } //1
		$a_02_1 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 05 03 [0-1e] c1 ?? 04 03 90 0a 0f 00 90 17 02 01 01 31 33 } //1
		$a_02_2 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 05 89 [0-1e] c1 ?? 04 03 90 0a 0f 00 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GR_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 [0-0f] 33 ?? 33 } //1
		$a_02_1 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 [0-0f] 31 ?? 31 } //1
		$a_02_2 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 90 0a 0f 00 33 ?? 33 } //1
		$a_02_3 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 90 0a 0f 00 31 ?? 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}