
rule Trojan_Win32_Delf_EC_MTB{
	meta:
		description = "Trojan:Win32/Delf.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d6 b1 19 8b c7 48 85 c0 7c 07 40 30 0a 42 48 75 fa 5f 5e 5b c3 } //6
		$a_01_1 = {46 41 44 47 52 51 53 50 43 55 54 57 56 69 68 6a } //1 FADGRQSPCUTWVihj
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1) >=7
 
}
rule Trojan_Win32_Delf_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Delf.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 32 30 2e 35 35 2e 31 39 36 2e 36 30 } //1 120.55.196.60
		$a_01_1 = {51 46 4e 54 55 31 4e 54 55 31 4e 54 55 31 4e 54 55 31 4e 54 55 31 4e 54 55 31 4e 54 51 41 3d 3d } //1 QFNTU1NTU1NTU1NTU1NTU1NTU1NTQA==
		$a_01_2 = {52 75 6e 55 72 6c 4b 65 77 } //1 RunUrlKew
		$a_01_3 = {51 46 64 58 56 31 64 58 56 31 64 58 51 41 3d 3d } //1 QFdXV1dXV1dXQA==
		$a_01_4 = {51 44 45 78 4d 54 45 78 4d 54 45 78 51 41 3d 3d } //1 QDExMTExMTExQA==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Delf_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Delf.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 43 3a } //1 Add-MpPreference -ExclusionPath C:
		$a_81_1 = {53 55 31 5a 57 56 56 6b } //1 SU1ZWVVk
		$a_81_2 = {56 33 68 6c 65 48 6c 33 4a 47 6c 32 64 6e 4e 32 50 67 3d 3d } //1 V3hleHl3JGl2dnN2Pg==
		$a_81_3 = {59 45 31 4a 56 56 56 52 59 41 3d 3d } //1 YE1JVVVRYA==
		$a_81_4 = {52 44 74 64 53 6b 39 55 56 55 4a 4e 54 55 5a 54 58 51 3d 3d } //1 RDtdSk9UVUJNTUZTXQ==
		$a_81_5 = {4d 47 64 36 5a 77 3d 3d } //1 MGd6Zw==
		$a_81_6 = {65 48 5a 35 61 51 3d 3d } //1 eHZ5aQ==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}