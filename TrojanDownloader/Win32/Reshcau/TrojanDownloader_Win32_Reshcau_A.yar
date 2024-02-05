
rule TrojanDownloader_Win32_Reshcau_A{
	meta:
		description = "TrojanDownloader:Win32/Reshcau.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 6f 74 08 3c 75 0f 85 } //01 00 
		$a_03_1 = {46 6a 00 6a 01 8d 45 ef 50 53 e8 90 01 04 85 c0 7f e3 90 00 } //01 00 
		$a_03_2 = {b8 1d 00 00 00 e8 90 01 04 40 ba 90 01 04 8a 44 02 ff 88 03 43 4e 75 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}