
rule TrojanDownloader_Win32_Boaxxe_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Boaxxe.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 25 31 21 64 21 2e 25 32 21 64 21 2e 25 33 21 64 21 2e 25 34 21 64 21 2f 49 4d 47 5f 90 02 01 25 35 21 90 01 01 21 2e 6a 70 67 90 00 } //02 00 
		$a_01_1 = {47 6c 6f 62 61 6c 5c 61 6c 61 7a 68 6b 76 6b 70 72 6d 69 64 } //01 00 
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 29 } //00 00 
	condition:
		any of ($a_*)
 
}