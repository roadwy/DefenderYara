
rule TrojanDownloader_Win32_Upatre_A{
	meta:
		description = "TrojanDownloader:Win32/Upatre.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00 } //1
		$a_03_1 = {8b 41 3c ff 75 90 01 01 03 c1 0f b7 90 03 01 01 48 50 06 6b 90 03 01 01 c9 d2 28 8d 84 90 03 01 01 01 02 d0 00 00 00 8b 90 03 01 01 70 78 14 03 90 03 01 01 70 78 10 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Upatre_A_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00 } //1
		$a_01_1 = {2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 32 00 30 00 31 00 33 00 2f 00 } //1 /wp-content/uploads/2013/
		$a_00_2 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}