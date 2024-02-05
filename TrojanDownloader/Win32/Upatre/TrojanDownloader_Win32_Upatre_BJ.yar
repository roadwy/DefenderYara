
rule TrojanDownloader_Win32_Upatre_BJ{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BJ,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 08 00 "
		
	strings :
		$a_01_0 = {50 8b c6 83 c0 24 8b 00 59 03 c8 03 4d f8 33 c0 66 8b 01 8b 4e 1c 8d 04 81 8b 4d f8 8b 04 01 03 c1 eb 02 } //08 00 
		$a_01_1 = {69 63 61 6e 68 61 7a 69 70 2e 63 6f 6d 00 2f 00 31 30 34 2e 33 36 2e 32 33 32 2e 32 31 39 } //02 00 
		$a_01_2 = {2f 73 6f 6b 61 31 31 2e 70 6e 67 00 33 38 2e 37 35 2e 33 38 2e 31 38 36 } //02 00 
		$a_01_3 = {31 38 38 2e 32 35 35 2e 32 34 31 2e 35 39 00 2f 73 6f 6b 61 31 31 2e 70 6e 67 00 53 4b 41 31 31 } //02 00 
		$a_01_4 = {32 34 2e 31 35 39 2e 31 35 33 2e 31 35 33 00 2f 73 6f 6b 61 31 31 2e 70 6e 67 } //00 00 
		$a_00_5 = {87 10 00 00 4d c2 b5 68 25 92 97 a4 08 b6 0d 62 58 1d } //00 00 
	condition:
		any of ($a_*)
 
}