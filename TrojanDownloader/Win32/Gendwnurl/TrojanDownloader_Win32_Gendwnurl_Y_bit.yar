
rule TrojanDownloader_Win32_Gendwnurl_Y_bit{
	meta:
		description = "TrojanDownloader:Win32/Gendwnurl.Y!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 61 6c 5c 62 77 61 70 69 5f 73 68 61 72 65 64 5f 6d 65 6d 6f 72 79 5f 67 61 6d 65 5f 6c 69 73 74 } //01 00 
		$a_03_1 = {40 00 c6 45 90 01 01 68 c6 45 90 01 01 74 c6 45 90 01 01 74 c6 45 90 01 01 70 90 00 } //01 00 
		$a_03_2 = {33 c0 89 45 90 01 01 89 45 90 09 08 00 c6 45 90 01 02 c6 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}