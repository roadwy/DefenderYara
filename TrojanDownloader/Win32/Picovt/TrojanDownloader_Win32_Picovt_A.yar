
rule TrojanDownloader_Win32_Picovt_A{
	meta:
		description = "TrojanDownloader:Win32/Picovt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 e8 00 00 00 00 8f 45 90 01 01 33 c0 66 8c c8 89 45 90 01 01 58 90 00 } //01 00 
		$a_03_1 = {ff d0 89 45 90 01 01 c7 45 90 01 01 75 72 6c 6d c7 45 90 01 01 6f 6e 2e 64 66 c7 45 90 01 01 6c 6c c6 45 90 01 01 00 85 c0 74 90 01 01 8d 4d 90 01 01 51 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}