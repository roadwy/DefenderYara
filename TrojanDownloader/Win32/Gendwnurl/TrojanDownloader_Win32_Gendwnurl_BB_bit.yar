
rule TrojanDownloader_Win32_Gendwnurl_BB_bit{
	meta:
		description = "TrojanDownloader:Win32/Gendwnurl.BB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 63 00 30 00 30 00 2e 00 63 00 63 00 2f 00 30 00 63 00 5f 00 64 00 61 00 74 00 61 00 2e 00 63 00 63 00 } //01 00  http://0c00.cc/0c_data.cc
		$a_03_1 = {4d 00 53 00 58 00 4d 00 4c 00 32 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 90 02 10 47 00 45 00 54 00 90 00 } //01 00 
		$a_03_2 = {4f 00 70 00 65 00 6e 00 90 01 04 53 00 65 00 6e 00 64 00 90 01 04 72 00 65 00 61 00 64 00 79 00 53 00 74 00 61 00 74 00 65 00 90 01 04 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}