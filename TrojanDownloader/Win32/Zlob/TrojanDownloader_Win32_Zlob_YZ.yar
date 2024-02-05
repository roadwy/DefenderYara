
rule TrojanDownloader_Win32_Zlob_YZ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.YZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 18 6a 00 6a 00 81 c2 96 00 00 00 52 55 ff 15 } //01 00 
		$a_03_1 = {bf 40 4b 4c 00 90 02 10 4e c1 ee 90 03 01 01 02 03 46 4f 75 90 00 } //01 00 
		$a_00_2 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}