
rule TrojanDownloader_AndroidOS_FakeSys_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/FakeSys.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 73 5f 63 61 6c 6c 5f 70 68 6f 6e 65 } //01 00 
		$a_00_1 = {64 6e 5f 62 6f 74 74 6f 6d 5f 73 6d 73 } //01 00 
		$a_00_2 = {77 61 70 2e 79 6c 78 64 74 77 77 2e 63 6f 6d } //01 00 
		$a_00_3 = {6b 74 2f 6c 69 73 74 2e 68 74 6d 6c } //01 00 
		$a_00_4 = {75 70 6c 6f 61 64 5f 64 65 76 69 63 65 49 6e 66 6f } //01 00 
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 41 6e 5a 68 69 41 70 6b } //01 00 
		$a_00_6 = {63 6c 69 63 6b 5f 6d 6f 6e 69 74 6f 72 5f 75 72 6c } //00 00 
		$a_00_7 = {5d 04 00 00 b6 } //a9 04 
	condition:
		any of ($a_*)
 
}