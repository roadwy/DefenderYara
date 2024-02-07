
rule TrojanDownloader_Win32_Zlob_AMZ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AMZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {8a 04 0a 32 44 24 20 88 01 49 ff 4c 24 10 75 f0 } //05 00 
		$a_02_1 = {25 ff 7f 00 00 c3 90 09 1d 00 a1 90 01 04 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 04 33 c0 66 a1 90 00 } //01 00 
		$a_01_2 = {67 6f 76 2d 61 76 61 73 74 21 } //01 00  gov-avast!
		$a_01_3 = {69 64 65 6f 00 } //01 00 
		$a_01_4 = {6b 69 6e 67 6f 66 74 68 65 77 6f 72 6c 64 } //00 00  kingoftheworld
	condition:
		any of ($a_*)
 
}