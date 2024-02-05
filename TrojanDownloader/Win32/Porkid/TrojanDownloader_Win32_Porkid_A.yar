
rule TrojanDownloader_Win32_Porkid_A{
	meta:
		description = "TrojanDownloader:Win32/Porkid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 50 68 90 01 04 8b 95 90 01 04 52 ff 15 90 01 04 89 45 90 01 01 83 7d 90 01 01 00 74 90 01 01 6a 00 90 00 } //01 00 
		$a_02_1 = {65 63 68 6f 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 20 22 90 02 10 2e 62 61 74 22 2c 30 2c 74 72 75 65 20 3e 3e 90 00 } //01 00 
		$a_00_2 = {2f 00 77 00 70 00 2f 00 47 00 45 00 4f 00 2f 00 67 00 65 00 6f 00 2e 00 70 00 68 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}