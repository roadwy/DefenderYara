
rule TrojanDownloader_Win32_Veload_A{
	meta:
		description = "TrojanDownloader:Win32/Veload.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 4c 24 18 c6 84 24 3c 0a 00 00 04 e8 90 01 04 89 5c 24 10 68 90 01 04 8d 4c 24 30 c6 84 24 3c 0a 00 00 06 e8 90 01 04 c6 84 24 38 0a 00 00 07 8b 44 24 2c ba 08 00 00 00 50 66 89 54 24 78 e8 90 00 } //01 00 
		$a_02_1 = {2f 2f 69 74 65 6d 90 02 04 76 65 72 73 69 6f 6e 90 02 04 64 6f 77 6e 75 72 6c 90 00 } //01 00 
		$a_02_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 04 6e 6f 76 65 6c 61 64 90 00 } //01 00 
		$a_00_3 = {63 6f 75 6e 74 2e 61 73 70 3f 65 78 65 63 3d 25 73 } //00 00  count.asp?exec=%s
	condition:
		any of ($a_*)
 
}