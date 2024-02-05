
rule TrojanDownloader_Win32_Farfli_PN_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.PN!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c e1 90 00 } //01 00 
		$a_01_1 = {54 43 50 43 6f 6e 6e 65 63 74 46 6c 6f 6f 64 54 68 72 65 61 64 2e 74 61 72 67 65 74 } //01 00 
		$a_03_2 = {68 74 74 70 3a 2f 2f 31 31 39 2e 32 34 39 2e 35 34 2e 31 31 33 2f 90 02 10 2e 65 78 65 90 00 } //01 00 
		$a_01_3 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //00 00 
	condition:
		any of ($a_*)
 
}