
rule TrojanDownloader_Win32_Kirssao_A{
	meta:
		description = "TrojanDownloader:Win32/Kirssao.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 45 dd 61 c6 45 de 6f c6 45 df 33 c6 45 e0 36 c6 45 e1 30 c6 45 e2 79 c6 45 e3 6e c6 45 e4 69 } //02 00 
		$a_01_1 = {c1 e6 06 3c 3d 75 09 c7 45 fc 01 00 00 00 eb 11 50 e8 } //01 00 
		$a_01_2 = {74 37 4f 7a 72 2b 6e 38 2f 4f 37 78 37 76 33 7a 37 76 33 75 37 2b 62 39 37 76 4c 78 2f 4c 69 32 73 4c 44 39 74 39 38 3d } //01 00 
		$a_01_3 = {33 2b 33 74 37 75 72 76 37 2b 37 76 37 2b 2f 66 39 2f 6a 33 2b 4e 2f 33 2b 50 66 34 33 2f 44 74 37 75 76 73 36 65 72 33 38 4f 72 76 37 66 6a 71 33 34 76 77 37 4f 2f 75 37 2f 66 66 69 71 } //00 00 
		$a_00_4 = {5d 04 00 } //00 ff 
	condition:
		any of ($a_*)
 
}