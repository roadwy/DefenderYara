
rule TrojanDropper_O97M_Obfuse_AJT_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.AJT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 52 50 54 68 67 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 58 45 6f 42 6a 20 2b 20 22 22 20 2b 20 72 4d 42 65 6d 29 } //01 00  Set RPThg = VBA.CreateObject(XEoBj + "" + rMBem)
		$a_01_1 = {5a 51 6c 45 74 20 4a 4b 68 58 4a 28 30 29 20 2b 20 22 33 32 20 22 20 2b 20 4a 4b 68 58 4a 28 33 29 2c 20 22 22 } //01 00  ZQlEt JKhXJ(0) + "32 " + JKhXJ(3), ""
		$a_01_2 = {62 59 76 6e 67 20 3d 20 53 70 6c 69 74 28 49 47 6d 64 4a 2c 20 73 56 4e 57 44 29 } //01 00  bYvng = Split(IGmdJ, sVNWD)
		$a_01_3 = {63 78 50 4a 78 28 4a 4b 68 58 4a 28 32 29 29 2e 65 78 65 63 20 28 43 6e 76 78 44 29 } //01 00  cxPJx(JKhXJ(2)).exec (CnvxD)
		$a_03_4 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 73 68 61 70 65 73 28 31 29 90 0c 02 00 47 41 69 7a 7a 20 3d 20 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}