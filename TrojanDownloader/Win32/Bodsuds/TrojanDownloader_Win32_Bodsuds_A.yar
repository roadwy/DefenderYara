
rule TrojanDownloader_Win32_Bodsuds_A{
	meta:
		description = "TrojanDownloader:Win32/Bodsuds.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3b c6 74 67 8d 8c 24 90 01 02 00 00 2b c1 40 50 8b c1 50 8d 84 24 90 01 02 00 00 50 ff 15 90 00 } //01 00 
		$a_01_1 = {ff 54 24 30 85 c0 74 0b ff 44 24 10 83 7c 24 10 14 7c da } //00 00 
	condition:
		any of ($a_*)
 
}