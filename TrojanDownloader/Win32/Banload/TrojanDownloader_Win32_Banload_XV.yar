
rule TrojanDownloader_Win32_Banload_XV{
	meta:
		description = "TrojanDownloader:Win32/Banload.XV,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 65 78 65 3b 2e 62 61 74 3b 2e 63 6f 6d 3b 2e 63 6d 64 3b } //01 00  .exe;.bat;.com;.cmd;
		$a_01_1 = {48 69 64 65 46 69 6c 65 45 78 74 } //01 00  HideFileExt
		$a_01_2 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 } //01 00  AntiVirusDisable
		$a_01_3 = {41 75 74 6f 55 70 64 61 74 65 44 69 73 61 62 6c 65 } //05 00  AutoUpdateDisable
		$a_03_4 = {8b 45 e4 83 f8 08 77 59 ff 24 85 90 01 03 00 22 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}