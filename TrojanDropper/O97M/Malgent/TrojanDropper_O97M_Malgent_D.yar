
rule TrojanDropper_O97M_Malgent_D{
	meta:
		description = "TrojanDropper:O97M/Malgent.D,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 3d 20 28 45 72 72 2e 4e 75 6d 62 65 72 20 3d 20 30 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //01 00 
		$a_00_1 = {2c 20 49 6e 74 28 52 6e 64 28 29 20 2a 20 4c 65 6e 28 } //01 00  , Int(Rnd() * Len(
		$a_00_2 = {43 61 6c 6c 20 4d 73 67 42 6f 78 28 22 53 6f 6d 65 74 68 69 6e 67 20 77 65 6e 74 20 77 72 6f 6e 67 21 20 50 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 74 6f 20 63 75 73 74 6f 6d 65 72 20 73 75 70 70 6f 72 74 21 22 2c 20 76 62 4f 4b 4f 6e 6c 79 2c 20 22 45 72 72 6f 72 22 29 } //01 00  Call MsgBox("Something went wrong! Please contact to customer support!", vbOKOnly, "Error")
		$a_00_3 = {20 3d 20 28 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 } //00 00   = (Environ("temp") & "\" & 
	condition:
		any of ($a_*)
 
}