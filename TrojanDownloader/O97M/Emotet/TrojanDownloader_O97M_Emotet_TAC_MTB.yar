
rule TrojanDownloader_O97M_Emotet_TAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.TAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 6e 73 20 77 75 20 64 62 20 6e 64 72 6f 6e 73 20 77 75 20 64 62 20 6e 64 6e 73 20 77 75 20 64 62 20 6e 64 63 22 20 2b 20 22 65 6e 73 20 77 75 20 64 62 20 6e 64 73 6e 73 20 77 75 20 64 62 20 6e 64 73 6e 73 20 77 75 20 64 62 20 6e 64 6e 73 20 77 75 20 64 62 20 6e 64 22 } //01 00   = "ns wu db ndrons wu db ndns wu db ndc" + "ens wu db ndsns wu db ndsns wu db ndns wu db nd"
		$a_01_1 = {20 3d 20 22 6e 73 20 77 75 20 64 62 20 6e 64 3a 77 6e 73 20 77 75 20 64 62 20 6e 64 6e 73 20 77 22 20 2b 20 22 75 20 64 62 20 6e 64 69 6e 6e 73 20 77 75 20 64 62 20 6e 64 33 6e 73 20 77 75 20 64 62 20 6e 64 32 6e 73 20 77 75 20 64 62 20 6e 64 5f 6e 73 20 77 75 20 64 62 20 6e 64 22 } //01 00   = "ns wu db nd:wns wu db ndns w" + "u db ndinns wu db nd3ns wu db nd2ns wu db nd_ns wu db nd"
		$a_01_2 = {20 3d 20 22 77 6e 73 20 77 75 20 64 62 20 6e 64 69 22 20 2b 20 22 6e 6e 73 20 77 75 20 64 62 20 6e 64 6d 6e 73 20 77 75 20 64 62 20 6e 64 67 6d 6e 73 20 77 75 20 64 62 20 6e 64 74 6e 73 20 77 75 20 64 62 20 6e 64 6e 73 20 77 75 20 64 62 20 6e 64 22 } //01 00   = "wns wu db ndi" + "nns wu db ndmns wu db ndgmns wu db ndtns wu db ndns wu db nd"
		$a_03_3 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 6e 73 20 77 22 20 2b 20 22 75 20 64 62 20 6e 64 22 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_4 = {2e 43 72 65 61 74 65 20 90 02 20 2c 20 90 02 20 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}