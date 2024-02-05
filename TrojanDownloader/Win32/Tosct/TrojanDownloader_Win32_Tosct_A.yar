
rule TrojanDownloader_Win32_Tosct_A{
	meta:
		description = "TrojanDownloader:Win32/Tosct.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 b0 65 c6 44 0c 10 2e 88 44 0c 11 c6 44 0c 12 78 88 44 0c 13 c6 44 0c 14 00 eb } //01 00 
		$a_01_1 = {8a 02 3c 65 75 05 83 ce ff eb 0e 2c 66 f6 d8 1b c0 83 e0 0c 83 c0 fe 8b f0 } //00 00 
	condition:
		any of ($a_*)
 
}