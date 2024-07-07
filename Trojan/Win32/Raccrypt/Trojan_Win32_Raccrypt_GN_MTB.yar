
rule Trojan_Win32_Raccrypt_GN_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 a3 90 01 04 c3 81 05 90 01 04 d6 38 00 00 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 5d c3 ff 35 90 01 04 6a 00 ff 15 90 01 04 a3 90 01 04 c3 81 05 90 01 04 d6 38 00 00 c3 ff 25 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 32 81 3d 90 01 04 03 02 00 00 90 0a 23 00 a1 90 01 04 8a 8c 30 90 01 04 8b 15 90 00 } //1
		$a_02_1 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 90 18 46 3b f7 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 c3 c3 b8 90 0a 50 00 c6 05 90 01 04 65 c6 05 90 01 04 63 c6 05 90 01 04 69 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb 90 02 06 c7 05 90 01 04 ff ff ff ff 90 02 0a 90 18 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00 90 00 } //10
		$a_02_1 = {b4 02 d7 cb 90 02 06 c7 05 90 01 04 ff ff ff ff 90 02 05 e8 90 01 04 8b 90 02 03 29 90 02 03 81 90 01 01 47 86 c8 61 ff 90 02 05 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 a3 90 01 04 c3 81 05 90 01 04 d6 38 00 00 c3 ff 25 90 00 } //1
		$a_02_1 = {6b 65 53 c6 05 90 01 04 72 c7 05 90 01 04 6e 65 6c 33 c7 05 90 01 04 64 6c 6c 00 66 c7 05 90 01 04 32 2e ff 15 90 00 } //1
		$a_02_2 = {ec b5 5a 31 c7 45 90 01 01 60 ca 40 72 c7 45 90 01 01 6f 13 1b 3d c7 45 90 01 01 03 6c 37 04 c7 45 90 01 01 bd 46 ea 13 c7 45 90 01 01 b0 29 f6 6d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 40 51 52 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 6f c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 63 c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 ff 15 90 00 } //1
		$a_02_1 = {51 b0 65 68 90 01 04 a2 90 01 04 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 00 c6 05 90 01 04 6e 90 02 05 c6 05 90 01 04 6c c6 05 90 01 04 33 c6 05 90 01 04 32 90 02 05 c6 05 90 01 04 6b ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {6b c6 05 a9 90 01 03 65 c6 05 90 01 04 72 c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 33 c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 6c 88 1d 90 01 04 ff 15 90 00 } //1
		$a_02_1 = {6b c6 05 c9 90 01 03 65 c6 05 90 01 04 72 c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 33 c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 6c 88 1d 90 01 04 ff 15 90 00 } //1
		$a_00_2 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3 } //1
		$a_00_3 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GN_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 01 45 fc 8b 45 fc 33 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}