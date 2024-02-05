
rule TrojanDownloader_AndroidOS_SMSAgent_A_xp{
	meta:
		description = "TrojanDownloader:AndroidOS/SMSAgent.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 53 65 6e 64 53 6d 73 20 74 68 72 65 61 64 20 73 74 61 72 74 } //01 00 
		$a_00_1 = {31 31 35 2e 32 38 2e 35 32 2e 34 33 3a 39 30 30 30 2e 31 32 33 2f 74 61 62 73 63 72 2f 73 79 62 62 2f 61 70 70 63 6c 69 65 6e 74 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 73 65 72 76 69 63 65 3f } //01 00 
		$a_00_2 = {6d 6d 70 6d 2f 67 65 74 57 69 6d 69 50 61 79 4d 6f 72 65 3f 63 68 61 6e 6e 65 6c 3d 30 30 30 31 26 69 6d 73 69 3d } //02 00 
		$a_00_3 = {63 6f 6d 2f 63 68 69 6e 61 4d 6f 62 69 6c 65 2f 4d 6f 62 69 6c 65 41 67 65 6e 74 } //01 00 
		$a_00_4 = {4d 53 47 5f 44 57 4f 4e 4c 4f 41 44 5f 41 50 50 44 4f 57 4e 4c 4f 41 44 5f 53 45 52 56 49 43 45 } //00 00 
		$a_00_5 = {5d 04 00 } //00 a8 
	condition:
		any of ($a_*)
 
}