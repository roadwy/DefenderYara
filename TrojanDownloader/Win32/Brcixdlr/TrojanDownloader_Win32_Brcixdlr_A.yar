
rule TrojanDownloader_Win32_Brcixdlr_A{
	meta:
		description = "TrojanDownloader:Win32/Brcixdlr.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 66 20 65 78 69 73 74 20 00 } //01 00  晩攠楸瑳 
		$a_03_1 = {43 83 fb 03 74 2b 6a 00 6a 00 8b 45 f8 e8 90 01 04 50 8b 45 fc e8 90 01 04 50 6a 00 e8 90 01 04 85 c0 75 d9 b2 01 90 00 } //01 00 
		$a_03_2 = {68 c4 09 00 00 e8 90 01 04 8d 55 90 01 01 b8 24 00 00 00 e8 90 01 04 8d 45 90 01 01 50 8d 4d 90 01 01 ba 90 01 04 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}