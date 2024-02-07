
rule TrojanDownloader_O97M_Ripnecs_A{
	meta:
		description = "TrojanDownloader:O97M/Ripnecs.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 28 45 6e 76 69 72 6f 6e 28 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 56 47 56 74 63 41 3d 3d 22 29 29 } //01 00  Shell(Environ(Base64Decode("VGVtcA=="))
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 4c 6c 68 4e 54 45 68 55 56 46 41 3d 22 29 29 } //01 00  CreateObject(Base64Decode("TWljcm9zb2Z0LlhNTEhUVFA="))
		$a_01_2 = {4f 70 65 6e 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 52 30 56 55 22 29 } //01 00  Open Base64Decode("R0VU")
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 51 55 52 50 52 45 49 75 55 33 52 79 5a 57 46 74 22 29 29 } //00 00  CreateObject(Base64Decode("QURPREIuU3RyZWFt"))
	condition:
		any of ($a_*)
 
}