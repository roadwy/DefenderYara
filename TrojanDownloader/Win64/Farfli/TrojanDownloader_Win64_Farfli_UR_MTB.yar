
rule TrojanDownloader_Win64_Farfli_UR_MTB{
	meta:
		description = "TrojanDownloader:Win64/Farfli.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 39 34 2e 31 34 36 2e 38 34 2e 32 34 33 3a 34 33 39 37 2f 37 37 } //01 00 
		$a_01_1 = {5c 72 75 6e 64 6c 6c 33 32 32 32 2e 65 78 65 } //01 00 
		$a_01_2 = {6f 6a 62 6b 63 67 2e 65 78 65 } //01 00 
		$a_01_3 = {5c 73 76 63 68 6f 73 74 2e 74 78 74 } //01 00 
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 76 63 68 6f 73 74 2e 74 78 74 } //01 00 
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00 
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}