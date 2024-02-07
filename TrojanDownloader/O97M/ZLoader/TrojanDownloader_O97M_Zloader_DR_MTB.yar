
rule TrojanDownloader_O97M_Zloader_DR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Zloader.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 6a 35 49 73 73 35 32 22 } //01 00  Environ$("USERPROFILE") + "\j5Iss52"
		$a_00_1 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 6e 35 49 73 35 73 35 32 22 } //02 00  Environ$("USERPROFILE") + "\n5Is5s52"
		$a_00_2 = {52 69 67 68 74 28 55 73 65 72 46 6f 72 6d 32 2e 54 61 67 2c 20 31 31 29 20 2b 20 54 65 6d 70 6f 72 61 72 79 20 2b 20 22 2e 78 6c 73 20 22 } //02 00  Right(UserForm2.Tag, 11) + Temporary + ".xls "
		$a_00_3 = {63 72 65 61 74 65 20 52 69 67 68 74 28 55 73 65 72 46 6f 72 6d 31 2e 43 61 70 74 69 6f 6e 2c 20 39 29 20 2b 20 54 65 6d 70 6f 72 61 72 79 20 2b 20 22 2e 64 6c 6c 2c 52 31 22 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 44 61 74 61 32 } //00 00  create Right(UserForm1.Caption, 9) + Temporary + ".dll,R1", Null, Null, Data2
	condition:
		any of ($a_*)
 
}