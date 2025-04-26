
rule TrojanDownloader_Win32_Neojit_A{
	meta:
		description = "TrojanDownloader:Win32/Neojit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 23 00 00 e8 } //1
		$a_03_1 = {c7 40 4c 80 10 00 00 c7 40 50 7c 08 00 00 ba ?? ?? ?? ?? 89 50 54 eb ?? 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Neojit_A_2{
	meta:
		description = "TrojanDownloader:Win32/Neojit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 6e 65 77 67 2f 61 2e 70 68 70 00 } //1
		$a_01_1 = {00 41 63 63 65 73 73 69 6e 67 20 74 68 65 20 73 65 72 76 65 72 2e 2e 2e 00 } //1
		$a_01_2 = {00 55 70 64 61 74 65 20 61 70 70 20 2d 3e 20 00 } //1
		$a_01_3 = {00 44 6f 77 6e 6c 6f 61 64 20 75 72 6c 20 3d 20 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Neojit_A_3{
	meta:
		description = "TrojanDownloader:Win32/Neojit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c6 25 01 00 00 80 79 05 48 83 c8 fe 40 85 c0 0f 85 ?? ?? 00 00 e9 90 16 0f b6 86 ?? ?? ?? ?? 0f b6 0a 2a c8 f6 d1 32 c8 88 0a e9 ?? ?? 00 00 00 00 00 00 } //10
		$a_03_1 = {6a 73 ff d0 e9 ?? ?? ?? ?? 00 00 00 00 90 09 0a 00 68 ?? ?? ?? ?? 68 } //1
		$a_03_2 = {6a 73 ff d0 eb ?? 00 00 00 00 90 09 0a 00 68 ?? ?? ?? ?? 68 } //1
		$a_03_3 = {8b 45 fc c6 00 68 (e9 90 16|eb 90 14) 8b 45 fc 40 89 18 (e9 90 16|eb 90 14) 8b 45 fc 83 c0 05 c6 00 c3 (e9 90 16|eb 90 14) ff 55 fc } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}