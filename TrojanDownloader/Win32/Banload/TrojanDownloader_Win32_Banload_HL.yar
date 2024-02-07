
rule TrojanDownloader_Win32_Banload_HL{
	meta:
		description = "TrojanDownloader:Win32/Banload.HL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_01_2 = {ff ff ff ff 07 00 00 00 5c 55 70 64 61 74 65 } //01 00 
		$a_03_3 = {8d 85 f7 fb ff ff 8b 55 fc e8 90 01 04 8d 85 f6 f7 ff ff 8b 55 f8 e8 90 01 04 6a 03 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 90 01 04 33 c0 90 00 } //01 00 
		$a_03_4 = {68 fe 00 00 00 8d 85 90 01 01 fe ff ff 50 e8 90 01 04 8d 55 fc 8d 85 90 01 01 fe ff ff e8 90 01 04 c7 05 90 01 04 01 00 00 00 8d 45 90 02 06 e8 90 01 04 6a 00 6a 00 8d 85 90 01 01 fe ff ff b9 90 01 04 8b 55 fc e8 90 01 04 8b 85 90 01 01 fe ff ff e8 90 01 04 50 8b 45 90 01 01 e8 90 01 04 50 6a 00 e8 90 01 04 8d 85 90 01 01 fe ff ff b9 90 01 04 8b 55 fc e8 90 01 04 8b 85 90 01 01 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}