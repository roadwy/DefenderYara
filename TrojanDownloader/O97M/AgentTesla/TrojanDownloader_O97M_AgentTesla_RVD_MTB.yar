
rule TrojanDownloader_O97M_AgentTesla_RVD_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 } //01 00  "m" + "s" + "h" + "t" + "a"
		$a_01_1 = {22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 69 61 6a 69 61 } //01 00  "https://www.bitly.com/asiajia
		$a_01_2 = {22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 61 68 64 6a 69 61 } //01 00  "https://www.bitly.com/asahdjia
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 40 20 5f 0d 0a 4e 61 6d 61 6b 42 6f 72 61 20 5f 0d 0a 2c 20 5f 0d 0a 6c 6f 72 61 32 } //01 00 
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 20 5f 0d 0a 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 45 39 34 41 2d 45 43 31 31 2d 39 37 32 43 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}