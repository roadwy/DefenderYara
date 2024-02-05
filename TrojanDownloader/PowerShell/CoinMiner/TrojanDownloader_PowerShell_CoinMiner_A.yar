
rule TrojanDownloader_PowerShell_CoinMiner_A{
	meta:
		description = "TrojanDownloader:PowerShell/CoinMiner.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 2e 00 65 00 73 00 74 00 6f 00 6e 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_00_1 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 63 00 68 00 61 00 74 00 63 00 64 00 6e 00 2e 00 6e 00 65 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}