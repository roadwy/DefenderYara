
rule Trojan_Win32_Ursnif_K{
	meta:
		description = "Trojan:Win32/Ursnif.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 2c 24 d3 cc d5 05 c3 } //01 00 
		$a_01_1 = {64 3a 5c 69 6e 5c 74 68 65 5c 74 6f 77 6e 5c 77 68 65 72 65 5c 61 68 75 6e 67 2e 70 64 62 } //01 00  d:\in\the\town\where\ahung.pdb
		$a_01_2 = {6d 61 6c 65 78 67 61 74 68 65 72 65 64 4e 6d 6f 76 65 74 68 2e 6d 61 6e 62 65 61 73 74 32 76 65 72 79 } //01 00  malexgatheredNmoveth.manbeast2very
		$a_01_3 = {43 54 24 79 68 72 74 67 66 64 72 34 68 65 72 79 } //00 00  CT$yhrtgfdr4hery
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}