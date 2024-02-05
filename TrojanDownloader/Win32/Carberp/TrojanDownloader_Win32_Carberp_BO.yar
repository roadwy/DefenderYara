
rule TrojanDownloader_Win32_Carberp_BO{
	meta:
		description = "TrojanDownloader:Win32/Carberp.BO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 46 0e 8a 43 0f 32 47 0f 88 46 0f 83 c3 10 83 c6 10 83 c1 10 8d 41 0f } //01 00 
		$a_03_1 = {b9 ff 09 00 00 33 c0 8d bd fd d7 ff ff f3 ab 66 ab aa 68 00 28 00 00 6a 00 68 90 01 04 e8 ec 28 00 00 83 c4 0c 68 00 28 00 00 6a 00 90 00 } //0a 00 
		$a_03_2 = {31 ee 0f b6 ee 0f b6 2c ed 90 01 04 c1 e5 08 31 ee 0f b6 ef 0f b6 2c ed 90 01 04 c1 e5 18 31 ee 0f b6 ea 0f b6 2c ed 90 01 04 31 ef 0f b6 ec 0f b6 2c ed 90 01 04 c1 e5 08 31 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}