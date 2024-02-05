
rule TrojanDownloader_Win32_Banload_JD{
	meta:
		description = "TrojanDownloader:Win32/Banload.JD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_00_1 = {3a 38 31 2f 73 76 63 2e 70 68 70 } //01 00 
		$a_01_2 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b } //00 00 
	condition:
		any of ($a_*)
 
}