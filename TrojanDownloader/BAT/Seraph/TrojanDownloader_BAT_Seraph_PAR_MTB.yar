
rule TrojanDownloader_BAT_Seraph_PAR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.PAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 20 0f 27 00 00 2f 33 00 d0 20 00 00 01 28 23 00 00 0a 02 74 01 00 00 1b 06 9a 72 73 00 00 70 17 28 24 00 00 0a 74 20 00 00 01 6f 25 00 00 0a de 03 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_80_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 72 6f 61 64 35 38 2f 68 6b 7a 66 63 2f 72 61 77 2f 6d 61 69 6e 2f 52 73 71 72 79 7a 6a 78 6c 62 68 2e 64 61 74 } //github.com/road58/hkzfc/raw/main/Rsqryzjxlbh.dat  00 00 
	condition:
		any of ($a_*)
 
}