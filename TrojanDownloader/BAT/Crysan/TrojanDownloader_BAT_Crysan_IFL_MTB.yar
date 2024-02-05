
rule TrojanDownloader_BAT_Crysan_IFL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Crysan.IFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 39 00 34 00 2e 00 32 00 36 00 2e 00 31 00 39 00 32 00 2e 00 31 00 33 00 31 00 } //01 00 
		$a_01_1 = {74 00 75 00 74 00 6f 00 72 00 69 00 61 00 6c 00 2e 00 67 00 79 00 61 00 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}