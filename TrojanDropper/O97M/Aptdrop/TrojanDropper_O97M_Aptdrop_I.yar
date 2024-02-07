
rule TrojanDropper_O97M_Aptdrop_I{
	meta:
		description = "TrojanDropper:O97M/Aptdrop.I,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 } //01 00  & Chr$(Val("&H" & Mid$(
		$a_00_1 = {20 3d 20 22 41 42 43 44 45 46 47 48 49 22 20 26 20 22 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39 2b 2f 22 } //00 00   = "ABCDEFGHI" & "JKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	condition:
		any of ($a_*)
 
}