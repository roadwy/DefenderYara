
rule TrojanDownloader_Linux_SAgnt_A_xp{
	meta:
		description = "TrojanDownloader:Linux/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 62 32 36 } //01 00 
		$a_03_1 = {77 67 65 74 20 2d 63 20 2d 50 20 2f 62 69 6e 20 68 74 74 70 3a 2f 2f 90 02 20 2f 69 6e 73 74 61 6c 6c 2e 74 61 72 90 00 } //01 00 
		$a_01_2 = {74 61 72 20 2d 78 66 20 2f 62 69 6e 2f 69 6e 73 74 61 6c 6c 2e 74 61 72 20 2d 43 20 2f 62 69 6e 2f } //01 00 
		$a_01_3 = {63 68 6d 6f 64 20 37 37 37 20 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 74 61 73 6b 67 72 6d 2d } //01 00 
		$a_01_4 = {6c 6e 20 2d 73 20 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 74 61 73 6b 67 72 6d 2d 20 2f 65 74 63 2f 72 63 2e 64 2f 72 63 35 2e 64 2f 74 61 73 6b 67 72 6d 2d } //00 00 
	condition:
		any of ($a_*)
 
}