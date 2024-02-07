
rule TrojanDownloader_Win32_Banload_APP{
	meta:
		description = "TrojanDownloader:Win32/Banload.APP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 70 68 6f 6e 65 75 70 64 61 74 65 2e 63 70 6c } //01 00  iphoneupdate.cpl
		$a_01_1 = {44 65 73 55 41 43 2e 62 61 74 } //01 00  DesUAC.bat
		$a_02_2 = {be 01 00 00 00 8b 45 90 01 01 0f b6 5c 30 ff 33 5d 90 01 01 3b fb 7c 90 01 01 81 c3 ff 00 00 00 2b df eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}