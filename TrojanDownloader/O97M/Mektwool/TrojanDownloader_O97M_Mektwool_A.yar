
rule TrojanDownloader_O97M_Mektwool_A{
	meta:
		description = "TrojanDownloader:O97M/Mektwool.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 22 20 41 6c 69 61 73 20 5f 0d 0a 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //01 00 
		$a_01_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 5f 0d 0a 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //01 00 
		$a_01_2 = {44 69 6d 20 55 72 6c 54 6f 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 20 41 73 20 53 74 72 69 6e 67 0d 0a 55 72 6c 54 6f 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 20 3d } //01 00 
		$a_01_3 = {62 79 4f 75 74 28 69 29 20 3d 20 28 28 62 79 49 6e 28 69 29 20 2b 20 4e 6f 74 20 62 45 6e 63 4f 72 44 65 63 29 20 58 6f 72 20 62 79 4b 65 79 28 6c 29 29 20 2d 20 62 45 6e 63 4f 72 44 65 63 } //00 00  byOut(i) = ((byIn(i) + Not bEncOrDec) Xor byKey(l)) - bEncOrDec
	condition:
		any of ($a_*)
 
}