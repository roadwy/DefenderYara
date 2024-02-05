
rule TrojanDownloader_Win32_Macanscab_A{
	meta:
		description = "TrojanDownloader:Win32/Macanscab.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 69 6d 61 67 65 73 2f 68 6f 74 6d 61 69 6c 2f 6d 61 63 2e 70 68 70 } //01 00 
		$a_01_1 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 20 22 68 74 74 70 3a } //01 00 
		$a_01_2 = {73 00 76 00 73 00 69 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}