
rule TrojanDownloader_Win32_Eltusk_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Eltusk.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 8f 56 22 0f 85 90 09 03 00 81 3c 90 00 } //01 00 
		$a_01_1 = {e1 42 96 f0 e8 } //01 00 
		$a_01_2 = {80 34 08 23 8a 14 08 89 f7 0f b6 d2 81 e7 ff 00 00 00 } //01 00 
		$a_01_3 = {73 74 25 30 33 69 30 30 30 30 30 2e 74 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}