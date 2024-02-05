
rule TrojanDownloader_Win32_Busky_A{
	meta:
		description = "TrojanDownloader:Win32/Busky.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 00 43 00 75 73 65 72 33 32 2e 64 6c 6c } //01 00 
		$a_00_1 = {42 00 43 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00 
		$a_00_2 = {43 00 6f 00 6d 00 53 00 70 00 65 00 63 00 } //01 00 
		$a_00_3 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 41 } //01 00 
		$a_02_4 = {81 ec 84 00 00 00 68 90 01 02 40 00 68 90 01 02 40 00 c3 90 00 } //01 00 
		$a_02_5 = {3b 4d 10 0f 90 02 08 8b 55 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}