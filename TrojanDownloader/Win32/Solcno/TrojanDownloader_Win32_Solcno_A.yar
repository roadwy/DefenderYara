
rule TrojanDownloader_Win32_Solcno_A{
	meta:
		description = "TrojanDownloader:Win32/Solcno.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 93 eb 9e 8d b4 26 00 00 00 00 c7 44 24 3b 43 6f 6e 6e c7 44 24 3f 65 63 74 69 31 ff c7 44 24 43 6f 6e 3a 20 c7 44 24 47 63 6c 6f 73 c7 44 24 4b 65 0d 0a 00 e9 0d ff ff ff 90 } //01 00 
		$a_01_1 = {c6 44 24 21 2e c6 44 24 22 62 c6 44 24 23 61 c6 44 24 24 74 } //01 00 
		$a_01_2 = {c7 40 08 5c 46 69 72 c7 40 0c 65 66 6f 78 c7 40 10 5c 50 72 6f c7 40 14 66 69 6c 65 66 c7 40 18 73 00 89 5c 24 08 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}