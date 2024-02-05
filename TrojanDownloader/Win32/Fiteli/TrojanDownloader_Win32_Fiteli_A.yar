
rule TrojanDownloader_Win32_Fiteli_A{
	meta:
		description = "TrojanDownloader:Win32/Fiteli.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 89 b5 cc ad ff ff e9 7c ff ff ff 53 8b 1d 90 01 02 40 00 ff d3 83 c4 04 8d 95 90 01 02 ff ff 52 ff 15 90 00 } //01 00 
		$a_03_1 = {e9 80 00 00 00 8d 55 e4 8d 8d e0 fb ff ff e8 90 01 02 ff ff 85 c0 74 6e ba 01 00 00 00 8b 8d e0 fb ff ff e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}