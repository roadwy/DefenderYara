
rule TrojanDownloader_O97M_Obfuse_RVAN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 41 73 63 28 4d 69 64 28 43 75 56 61 75 69 48 70 38 2c 20 49 49 66 28 4a 36 39 70 6d 75 41 76 39 20 4d 6f 64 20 4c 65 6e 28 43 75 56 61 75 69 48 70 38 29 } //1 Chr(Asc(Mid(CuVauiHp8, IIf(J69pmuAv9 Mod Len(CuVauiHp8)
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 63 35 59 42 57 45 36 59 50 20 2b 20 72 65 77 44 48 31 73 38 44 20 2b 20 4c 52 70 42 63 4b 6a 70 6f 20 2b 20 77 4a 39 77 6f 31 58 6c 78 29 29 } //1 Debug.Print (VBA.Shell(c5YBWE6YP + rewDH1s8D + LRpBcKjpo + wJ9wo1Xlx))
		$a_01_2 = {58 6f 72 20 41 73 63 28 4d 69 64 28 70 57 74 4b 4c 56 4b 75 38 2c 20 4a 36 39 70 6d 75 41 76 39 2c 20 31 29 } //1 Xor Asc(Mid(pWtKLVKu8, J69pmuAv9, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}