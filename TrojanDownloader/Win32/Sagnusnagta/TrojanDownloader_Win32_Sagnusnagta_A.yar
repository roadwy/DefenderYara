
rule TrojanDownloader_Win32_Sagnusnagta_A{
	meta:
		description = "TrojanDownloader:Win32/Sagnusnagta.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b d7 81 e2 03 00 00 80 79 05 4a 83 ca fc 42 8a 44 14 18 8a 0e 32 c8 47 88 0e 46 3b f3 72 e1 5f 5e 5b c3 } //01 00 
		$a_02_1 = {25 73 25 64 25 64 2e 65 78 65 90 02 10 63 3a 5c 90 02 03 2e 74 78 74 90 00 } //02 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 90 02 08 2e 73 77 68 6d 7a 71 2e 63 6f 6d 2f 90 00 } //01 00 
		$a_03_3 = {55 52 4c 00 90 02 04 25 64 90 02 04 63 3a 5c 90 02 03 2e 64 61 74 90 00 } //01 00 
		$a_01_4 = {3f 6e 3d 25 73 26 69 64 3d 25 73 26 74 3d 25 73 26 69 3d 25 64 } //00 00  ?n=%s&id=%s&t=%s&i=%d
	condition:
		any of ($a_*)
 
}