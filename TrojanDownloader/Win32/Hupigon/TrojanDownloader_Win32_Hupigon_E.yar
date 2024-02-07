
rule TrojanDownloader_Win32_Hupigon_E{
	meta:
		description = "TrojanDownloader:Win32/Hupigon.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 75 72 6c 6d 6f 6f 6e 6b 2e 64 6c 6c } //01 00  %s\urlmoonk.dll
		$a_01_1 = {25 73 4c 6f 61 64 6c 6f 67 67 69 6e 67 } //01 00  %sLoadlogging
		$a_00_2 = {6a 0c 50 68 04 00 00 98 ff b6 a8 00 00 00 } //01 00 
		$a_00_3 = {8b 8e 68 a4 00 00 83 c4 1c 89 84 8e 28 08 00 00 ff 86 68 a4 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}