
rule TrojanDownloader_Win32_Banload_KJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.KJ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 0e 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 00 00 0a 00 6a 00 6a 00 68 90 01 01 00 00 00 6a 90 01 01 6a 00 6a 00 90 01 01 6a 00 b9 90 01 04 ba 90 01 04 b8 90 01 04 e8 90 01 04 a3 90 01 04 90 03 02 04 6a 00 68 90 01 04 90 03 02 06 6a 64 68 90 01 02 00 00 6a 00 a1 90 01 04 50 e8 90 01 04 eb 0c 90 00 } //02 00 
		$a_01_1 = {75 72 8b 16 8b c2 89 45 ec 8b 45 ec 85 c0 74 05 83 e8 04 8b 00 83 f8 03 7e 4e } //02 00 
		$a_03_2 = {74 50 6a 00 8d 55 90 01 01 b8 90 01 04 e8 90 01 04 ff 75 90 01 01 ff 75 fc b8 90 01 04 8d 55 90 01 01 e8 90 01 04 ff 75 90 01 01 8d 45 90 01 01 ba 03 00 00 00 90 00 } //02 00 
		$a_03_3 = {7e 4f bf 01 00 00 00 8b 45 fc 0f b6 5c 38 ff 80 fb 5c 75 24 ff 75 f8 8d 45 90 01 01 8b d3 e8 90 00 } //02 00 
		$a_03_4 = {50 68 00 04 00 00 8d 85 90 01 02 ff ff 50 56 e8 90 01 04 6a 00 8d 95 90 01 02 ff ff 8b 4d 90 01 01 8d 85 90 01 02 ff ff e8 90 01 04 e8 90 01 04 83 7d 90 01 01 00 75 c9 90 00 } //02 00 
		$a_01_5 = {5a 3a 5c 44 72 6f 70 62 6f 78 5c 4d 79 20 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e } //01 00  Z:\Dropbox\My Dropbox\Projetos\Javan
		$a_01_6 = {3a 49 4e 49 43 49 4f } //01 00  :INICIO
		$a_01_7 = {44 45 4c 41 50 50 20 45 4c 53 45 20 47 4f 54 4f 20 44 45 4c 42 41 54 } //01 00  DELAPP ELSE GOTO DELBAT
		$a_01_8 = {3a 44 45 4c 41 50 50 } //01 00  :DELAPP
		$a_01_9 = {3a 44 45 4c 42 41 54 } //01 00  :DELBAT
		$a_01_10 = {53 68 61 72 65 64 41 50 50 73 22 3d 2d } //01 00  SharedAPPs"=-
		$a_01_11 = {4e 45 54 20 53 54 41 52 54 20 57 6d 69 41 70 73 72 76 33 32 00 } //01 00 
		$a_01_12 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00 } //01 00 
		$a_01_13 = {32 33 38 37 37 34 39 31 31 00 } //00 00  ㌲㜸㐷ㄹ1
	condition:
		any of ($a_*)
 
}