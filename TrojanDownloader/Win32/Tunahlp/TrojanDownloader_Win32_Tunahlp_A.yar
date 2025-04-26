
rule TrojanDownloader_Win32_Tunahlp_A{
	meta:
		description = "TrojanDownloader:Win32/Tunahlp.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {81 44 24 44 08 5d cf 76 81 44 24 30 08 5d cf 76 81 44 24 38 08 5d cf 76 81 44 24 24 08 5d cf 76 } //5
		$a_01_1 = {09 3e 4d ce a5 34 bf 73 7e 6e 7d e6 74 79 c0 6a } //1
		$a_01_2 = {25 00 88 c3 71 26 ba 3b c2 4d eb 1c 20 64 54 9c } //1
		$a_01_3 = {b0 d6 3e 38 b1 1b 8a f7 cc 8d 40 77 4a 41 e8 d4 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}