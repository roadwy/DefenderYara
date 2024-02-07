
rule TrojanDownloader_Win32_Adload_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Adload.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 2f 77 77 77 2e 4d 6f 4b 65 41 44 2e 63 } //01 00  //www.MoKeAD.c
		$a_00_1 = {2f 2f 77 31 2e 4d 6f 4b 65 41 44 2e 63 } //01 00  //w1.MoKeAD.c
		$a_00_2 = {2f 2f 77 32 2e 4d 6f 4b 65 41 44 2e 63 } //01 00  //w2.MoKeAD.c
		$a_00_3 = {2f 2f 77 33 2e 4d 6f 4b 65 41 44 2e 63 } //01 00  //w3.MoKeAD.c
		$a_00_4 = {2f 2f 77 34 2e 4d 6f 4b 65 41 44 2e 63 } //01 00  //w4.MoKeAD.c
		$a_00_5 = {2f 2f 77 35 2e 4d 6f 4b 65 41 44 2e 63 } //01 00  //w5.MoKeAD.c
		$a_00_6 = {53 65 72 53 65 74 75 70 2e 65 78 65 } //01 00  SerSetup.exe
		$a_02_7 = {43 68 65 63 6b 55 70 64 61 74 90 01 0a 2e 62 61 6b 90 01 0c 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}