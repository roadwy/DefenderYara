
rule Backdoor_BAT_Crysan_ABX_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 09 11 04 28 10 90 01 02 0a 6f 11 90 01 02 0a 13 07 72 01 90 01 02 70 13 08 28 12 90 01 02 0a 11 07 6f 13 90 01 02 0a 13 09 28 14 90 01 02 0a 13 0a 1a 8d 01 90 01 02 01 13 0e 11 0e 16 11 0a a2 11 0e 90 00 } //01 00 
		$a_03_1 = {13 0b 11 09 72 b6 90 01 02 70 6f 16 90 01 02 0a 11 05 20 00 90 01 02 00 14 14 11 0b 74 01 90 01 02 1b 6f 17 90 01 02 0a 90 0a 41 00 17 7e 15 90 01 02 0a a2 11 0e 18 11 08 28 02 90 01 02 06 a2 11 0e 19 17 8c 19 90 01 02 01 a2 11 0e 90 00 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //01 00  get_ExecutablePath
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}