
rule TrojanDownloader_Win32_Anedl_A{
	meta:
		description = "TrojanDownloader:Win32/Anedl.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 76 20 22 6c 6f 61 64 22 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 } //01 00 
		$a_03_1 = {80 7d fb 01 75 90 01 01 81 fb b8 0b 00 00 76 90 01 01 6a 01 6a 00 6a 00 90 00 } //01 00 
		$a_03_2 = {68 e8 03 00 00 e8 90 01 04 6a 00 8d 45 90 01 01 e8 90 01 04 ff 75 90 1b 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}