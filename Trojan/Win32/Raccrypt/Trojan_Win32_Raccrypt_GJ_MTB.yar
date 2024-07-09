
rule Trojan_Win32_Raccrypt_GJ_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff [0-0a] 90 18 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 52 c0 5d 8b 45 ?? 83 25 ?? ?? ?? ?? 00 03 c3 50 8b c3 c1 e0 04 03 45 ?? 90 18 33 44 24 04 c2 ?? ?? 81 00 40 36 ef c6 c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-08] c7 05 } //1
		$a_02_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 03 [0-1e] c1 ?? 04 03 [0-08] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 90 0a 32 00 c1 ?? 04 03 [0-0f] c1 ?? 05 03 [0-1e] 90 17 02 01 01 31 33 90 0a 14 00 c7 05 } //1
		$a_02_1 = {b4 21 e1 c5 90 0a 32 00 c1 ?? 05 03 [0-0f] c1 ?? 04 03 [0-1e] 90 17 02 01 01 31 33 90 0a 14 00 c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 [0-0f] c1 ?? 05 [0-0f] 33 [0-08] c7 05 } //1
		$a_02_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 [0-0f] c1 ?? 04 [0-0f] 33 [0-08] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {36 23 01 00 90 02 06 88 0c 32 8b e5 5d c3 } //1
		$a_02_1 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-06] e8 ?? ?? ?? ?? 8b [0-03] 29 [0-03] 68 ?? ?? ?? ?? 8d [0-03] 52 e8 [0-07] 0f 85 } //10
		$a_02_2 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 ?? 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=11
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 94 31 36 23 01 00 88 ?? ?? 30 81 c4 ?? ?? ?? ?? c3 } //1
		$a_00_1 = {36 23 01 00 88 0c 32 8b e5 5d c3 } //1
		$a_02_2 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-03] e8 ?? ?? ?? ?? 8b ca e8 ?? ?? ?? ?? 8b [0-03] 29 [0-03] 8d [0-03] e8 ?? ?? ?? ?? 4f 8b [0-03] 0f 85 } //10
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*10) >=11
 
}
rule Trojan_Win32_Raccrypt_GJ_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {72 c3 c3 55 90 0a 72 00 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 } //1
		$a_02_1 = {55 8b ec b8 90 0a 72 00 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}