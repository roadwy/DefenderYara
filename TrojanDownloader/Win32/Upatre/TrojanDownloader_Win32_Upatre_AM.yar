
rule TrojanDownloader_Win32_Upatre_AM{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } //01 00  猥猥─屳猥漀数n整瑸⨯愀灰楬慣楴湯⨯䜀呅䴀穯汩慬㐯〮
		$a_03_1 = {57 ab 33 c0 ab e2 fd 8b 7d 90 01 01 57 ab ab ab ab 8b f8 90 00 } //01 00 
		$a_01_2 = {03 f2 51 57 8b 06 59 33 c1 89 06 03 f2 59 47 e2 f1 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}