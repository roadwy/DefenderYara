
rule TrojanDropper_O97M_Zdowbot_A{
	meta:
		description = "TrojanDropper:O97M/Zdowbot.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 67 65 6d 69 6e 69 20 54 68 65 6e 20 6c 61 6d 61 72 63 6b 69 61 6e 20 3d 20 4c 65 66 74 24 28 6c 61 6d 61 72 63 6b 69 61 6e 2c 20 4c 65 6e 28 6c 61 6d 61 72 63 6b 69 61 6e 29 20 2d 20 67 65 6d 69 6e 69 29 } //01 00  If gemini Then lamarckian = Left$(lamarckian, Len(lamarckian) - gemini)
		$a_03_1 = {3d 20 4d 69 64 28 22 90 02 10 77 69 90 02 10 22 2c 20 31 31 2c 20 32 29 20 26 20 4c 43 61 73 65 28 22 4e 6d 47 6d 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 5c 3a 73 74 22 29 90 00 } //01 00 
		$a_03_2 = {26 20 4c 43 61 73 65 28 22 4f 4f 54 22 29 20 2b 20 52 69 67 68 74 28 22 90 02 10 63 69 6d 76 32 22 2c 20 36 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}