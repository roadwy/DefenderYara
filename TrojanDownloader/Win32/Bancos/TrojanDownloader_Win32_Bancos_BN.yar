
rule TrojanDownloader_Win32_Bancos_BN{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 07 c7 45 90 01 01 01 00 00 00 83 f3 90 01 01 8d 45 90 01 01 50 89 5d 90 01 01 c6 45 90 01 01 00 8d 55 90 01 01 33 c9 b8 90 01 04 e8 90 01 04 8b 55 90 01 01 8d 45 90 01 01 e8 90 01 04 8b f3 47 ff 4d 90 01 01 75 a8 90 00 } //01 00 
		$a_03_1 = {6a 05 ff b3 7c 03 00 00 68 90 01 04 ff b3 80 03 00 00 8d 45 e4 ba 03 00 00 00 e8 90 01 04 8b 45 e4 e8 90 01 04 50 e8 90 01 04 68 e8 03 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}