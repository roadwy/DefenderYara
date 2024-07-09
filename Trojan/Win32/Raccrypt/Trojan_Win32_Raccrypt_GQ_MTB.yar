
rule Trojan_Win32_Raccrypt_GQ_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? [0-04] 8b 4c 24 ?? 33 ?? 24 ?? 03 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {88 0c 02 40 3b 05 } //1
		$a_02_1 = {03 c8 c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 55 ?? 33 d1 33 d3 8d 8d ?? ?? ?? ?? 89 55 ?? 90 18 29 11 c3 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f0 2c cb 49 c7 [0-05] b9 61 c2 1b c7 [0-05] 13 f9 47 7a c7 [0-05] 21 47 ef 5f c7 [0-05] a9 4e 9a 0f c7 [0-05] 0c 04 b3 5e } //1
		$a_02_1 = {a4 94 77 17 c7 [0-05] a3 af d2 0e c7 [0-05] 8f 06 8d 6a c7 [0-05] 5d 9f f4 68 c7 [0-05] 72 83 38 04 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff [0-0a] 90 18 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00 } //10
		$a_02_1 = {b4 21 e1 c5 [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff [0-05] e8 ?? ?? ?? ?? 8b [0-03] 29 [0-05] 81 ?? 47 86 c8 61 ff [0-05] 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-0f] 31 } //1
		$a_02_1 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 05 03 [0-1e] c1 ?? 04 03 [0-0f] 31 } //1
		$a_02_2 = {bb 9b c6 a0 04 8b [0-14] c1 ?? 05 89 [0-1e] c1 ?? 04 03 [0-0f] 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 b3 6c 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 ff 15 } //1
		$a_02_1 = {b0 74 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 6f a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 a2 ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 [0-0f] c7 05 [0-1e] 90 17 02 01 01 31 33 } //1
		$a_02_1 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 [0-0f] c7 05 [0-1e] 90 17 02 01 01 31 33 } //1
		$a_02_2 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 [0-0f] c7 05 90 0a 1e 00 90 17 02 01 01 31 33 } //1
		$a_02_3 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 [0-0f] c7 05 90 0a 1e 00 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GQ_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 03 [0-0f] 90 17 02 01 01 31 33 [0-14] c7 05 } //1
		$a_02_1 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 03 [0-0f] 90 17 02 01 01 31 33 [0-14] c7 05 } //1
		$a_02_2 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 03 90 0a 0f 00 90 17 02 01 01 31 33 [0-14] c7 05 } //1
		$a_02_3 = {b4 21 e1 c5 [0-0d] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 03 90 0a 0f 00 90 17 02 01 01 31 33 [0-14] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}