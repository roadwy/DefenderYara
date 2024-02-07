
rule TrojanDropper_O97M_FlawedAmmyy_A{
	meta:
		description = "TrojanDropper:O97M/FlawedAmmyy.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {4b 69 6c 6c 41 72 72 61 79 20 90 02 10 20 26 20 22 5c 90 02 20 2e 62 69 6e 22 90 00 } //01 00 
		$a_00_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 22 20 2b 20 22 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject("Shell." + "Application")
		$a_02_2 = {28 22 78 6c 5c 65 6d 62 65 64 64 69 6e 67 73 5c 90 02 20 2e 62 69 6e 22 29 90 00 } //01 00 
		$a_02_3 = {4e 65 77 56 61 6c 75 6a 65 20 90 02 10 20 2b 20 22 5c 90 02 20 2e 22 20 2b 20 22 62 69 6e 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}