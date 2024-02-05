
rule TrojanDownloader_Win32_Upatre_CF{
	meta:
		description = "TrojanDownloader:Win32/Upatre.CF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 1d bc 70 40 00 b9 7f 96 98 00 e8 00 40 00 00 } //01 00 
		$a_01_1 = {ff d0 6a 0a ff 35 e4 70 40 00 6a 00 ff 35 44 70 40 00 e8 0c 00 00 00 } //01 00 
		$a_01_2 = {68 00 01 00 00 68 00 01 00 00 68 80 00 00 00 68 90 00 00 00 68 00 00 cf 00 68 00 70 40 00 68 2b 70 40 00 6a 00 ff 15 e4 80 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}