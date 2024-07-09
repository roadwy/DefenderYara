
rule TrojanDownloader_PowerShell_LodPey_A{
	meta:
		description = "TrojanDownloader:PowerShell/LodPey.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 65 00 76 00 32 00 30 00 31 00 2e 00 63 00 64 00 6e 00 69 00 6d 00 61 00 67 00 65 00 73 00 2e 00 78 00 79 00 7a 00 3a 00 38 00 30 00 2f 00 90 1d 15 00 2f 00 90 1d 15 00 27 00 29 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}