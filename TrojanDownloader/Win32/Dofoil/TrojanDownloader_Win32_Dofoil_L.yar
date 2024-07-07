
rule TrojanDownloader_Win32_Dofoil_L{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 50 e8 90 01 04 8b 15 90 01 04 89 02 68 90 00 } //1
		$a_03_1 = {8b 44 24 0c 50 a1 90 01 04 8b 00 ff d0 3d 03 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Dofoil_L_2{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3f 63 6d 64 3d 67 65 74 6c 6f 61 64 26 } //1 ?cmd=getload&
		$a_01_1 = {eb 08 e8 09 00 00 00 89 46 fc ad 85 c0 75 f3 c3 56 89 c2 8b 45 3c 8b 7c 28 78 01 ef } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Dofoil_L_3{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 03 07 00 01 00 } //1
		$a_01_1 = {89 83 b0 00 00 00 } //1
		$a_01_2 = {8a 06 32 c2 88 07 46 47 49 83 f9 00 75 f2 } //2
		$a_01_3 = {68 56 71 64 4f 8b 03 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}