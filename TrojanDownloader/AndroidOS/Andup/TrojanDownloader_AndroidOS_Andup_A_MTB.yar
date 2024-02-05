
rule TrojanDownloader_AndroidOS_Andup_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/Andup.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 65 65 2e 63 6f 6d 2f 31 2e 61 70 6b } //01 00 
		$a_00_1 = {73 79 73 63 6f 72 65 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 44 4f 57 4e 4c 4f 41 44 5f 48 49 44 45 } //01 00 
		$a_00_2 = {73 74 61 72 74 44 6f 77 6e 6c 6f 61 64 34 41 64 } //01 00 
		$a_00_3 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //01 00 
		$a_00_4 = {6b 69 6c 6c 5f 73 65 6c 66 } //00 00 
		$a_00_5 = {5d 04 00 } //00 8b 
	condition:
		any of ($a_*)
 
}