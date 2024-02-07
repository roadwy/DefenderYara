
rule TrojanDownloader_Win32_Bancos_BQ{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 d0 6a 0c 50 6a 10 68 80 08 00 00 e8 90 01 04 35 90 00 } //01 00 
		$a_01_1 = {6e 6f 76 6f 6c 6f 61 64 65 72 00 } //01 00 
		$a_00_2 = {4c 00 6f 00 61 00 64 00 65 00 72 00 5f 00 56 00 42 00 5f 00 64 00 69 00 64 00 75 00 2e 00 76 00 62 00 70 00 } //00 00  Loader_VB_didu.vbp
	condition:
		any of ($a_*)
 
}