
rule TrojanDownloader_Win32_Bancos_FU{
	meta:
		description = "TrojanDownloader:Win32/Bancos.FU,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 69 74 75 6c 6f 3d } //01 00 
		$a_01_1 = {74 65 78 74 6f 3d } //01 00 
		$a_01_2 = {41 43 37 39 42 32 34 37 44 44 35 41 41 45 37 42 38 30 } //05 00 
		$a_01_3 = {70 72 61 71 75 65 6d 3d } //0a 00 
		$a_03_4 = {8b c3 8b 08 ff 51 38 68 90 01 02 47 00 8d 55 90 01 01 8b 90 02 02 e8 90 01 02 ff ff ff 75 90 01 01 68 90 01 02 47 00 8d 45 90 01 01 ba 03 00 00 00 e8 90 01 02 f8 ff 8b 55 90 01 01 8b c3 8b 08 ff 51 38 8d 55 90 01 01 8b 90 01 01 8b 08 ff 51 90 01 01 8b 4d 90 01 01 8d 45 90 01 01 ba 90 01 02 47 00 e8 90 01 03 ff 8b 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}