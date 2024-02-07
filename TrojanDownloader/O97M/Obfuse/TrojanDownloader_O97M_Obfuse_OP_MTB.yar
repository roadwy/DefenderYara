
rule TrojanDownloader_O97M_Obfuse_OP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f 6d 6f 6e 69 63 61 70 65 63 65 72 65 2e 69 74 2f 4e 36 4e 77 51 48 52 39 52 49 50 6f 33 70 46 2e 65 78 65 22 } //01 00  = "https://monicapecere.it/N6NwQHR9RIPo3pF.exe"
		$a_01_1 = {2e 4f 70 65 6e 20 44 65 76 6c 70 2c 20 44 6f 77 6e 6c 6f 61 64 69 6d 61 67 65 5f 55 52 4c 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 } //01 00  .Open Devlp, Downloadimage_URL, False, "username", "password
		$a_01_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 53 65 72 76 65 72 2e 67 69 66 22 29 } //00 00  .SaveToFile ("Server.gif")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_OP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 73 6d 62 79 74 65 20 3d 20 61 73 6d 62 79 74 65 20 2b 20 30 2e } //01 00  asmbyte = asmbyte + 0.
		$a_01_1 = {2a 20 46 69 78 28 } //01 00  * Fix(
		$a_01_2 = {2a 20 54 29 } //01 00  * T)
		$a_01_3 = {26 20 22 7c 22 20 26 20 42 20 26 20 22 7c 22 } //01 00  & "|" & B & "|"
		$a_03_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 90 02 30 2e 62 61 74 22 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_03_5 = {26 20 22 36 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 39 2f 30 37 2f 90 02 10 2e 65 78 65 20 43 3a 5c 90 02 30 2e 65 78 65 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_OP_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 47 38 77 7a 35 6b 38 74 51 30 64 75 38 42 } //01 00  Debug.Print G8wz5k8tQ0du8B
		$a_01_1 = {43 4c 6e 67 28 28 32 2e 31 30 37 32 39 36 31 33 37 33 33 39 30 36 20 2a 20 34 36 36 29 29 } //01 00  CLng((2.10729613733906 * 466))
		$a_01_2 = {77 64 42 75 6c 67 61 72 69 61 6e } //01 00  wdBulgarian
		$a_01_3 = {28 2d 34 38 32 20 2d 20 77 64 54 65 78 74 75 72 65 32 35 50 65 72 63 65 6e 74 29 } //01 00  (-482 - wdTexture25Percent)
		$a_01_4 = {43 68 72 28 43 4c 6e 67 28 28 41 73 63 57 28 22 69 22 29 } //01 00  Chr(CLng((AscW("i")
		$a_01_5 = {43 6c 6f 73 65 20 23 43 4c 6e 67 28 28 77 64 4a 75 73 74 69 66 69 63 61 74 69 6f 6e 4d 6f 64 65 43 6f 6d 70 72 65 73 73 20 58 6f 72 20 77 64 53 65 63 74 69 6f 6e 44 69 72 65 63 74 69 6f 6e 52 74 6c 29 29 } //00 00  Close #CLng((wdJustificationModeCompress Xor wdSectionDirectionRtl))
	condition:
		any of ($a_*)
 
}