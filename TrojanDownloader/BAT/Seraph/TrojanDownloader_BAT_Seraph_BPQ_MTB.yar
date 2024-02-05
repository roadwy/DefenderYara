
rule TrojanDownloader_BAT_Seraph_BPQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.BPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0c 08 2d 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00 
		$a_81_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00 
		$a_81_4 = {52 65 70 6c 61 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}