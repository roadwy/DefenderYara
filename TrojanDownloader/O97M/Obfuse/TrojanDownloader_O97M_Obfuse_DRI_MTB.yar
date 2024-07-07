
rule TrojanDownloader_O97M_Obfuse_DRI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DRI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 28 22 64 22 29 29 29 29 20 26 20 43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 57 28 22 61 22 29 29 29 29 20 26 20 43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 28 22 74 22 29 29 29 29 } //1 & ChrW(CLng((Asc("d")))) & ChrW(CLng((AscW("a")))) & ChrW(CLng((Asc("t"))))
		$a_01_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 28 43 4c 6e 67 28 28 77 64 41 72 74 41 72 63 68 65 64 53 63 61 6c 6c 6f 70 73 20 41 6e 64 20 28 28 77 64 44 69 61 6c 6f 67 54 6f 6f 6c 73 55 6e 70 72 6f 74 65 63 74 44 6f 63 75 6d 65 6e 74 20 2b 20 33 37 32 23 29 20 2d 20 37 39 38 23 29 29 29 29 20 26 20 43 68 72 57 28 43 4c 6e 67 28 28 77 64 44 69 61 6c 6f 67 45 64 69 74 52 65 70 6c 61 63 65 20 41 6e 64 20 77 64 4b 65 79 50 29 29 29 20 5f } //1 = Join(Array(Chr(CLng((wdArtArchedScallops And ((wdDialogToolsUnprotectDocument + 372#) - 798#)))) & ChrW(CLng((wdDialogEditReplace And wdKeyP))) _
		$a_01_2 = {41 73 63 28 4c 65 66 74 24 28 4d 69 64 24 28 47 77 6b 57 74 39 59 56 65 71 66 4f 2c 20 79 48 55 49 4d 7a 58 6b 75 42 73 4a 29 2c } //1 Asc(Left$(Mid$(GwkWt9YVeqfO, yHUIMzXkuBsJ),
		$a_01_3 = {2e 43 72 65 61 74 65 20 56 4d 4c 72 75 51 53 70 66 62 47 4c 6c 76 79 6b 2c 20 4e 75 6c 6c 2c 20 66 45 6f 46 75 35 64 67 5a 48 74 } //1 .Create VMLruQSpfbGLlvyk, Null, fEoFu5dgZHt
		$a_01_4 = {2b 20 43 68 72 28 43 4c 6e 67 28 28 77 64 4b 65 79 4e 75 6d 65 72 69 63 39 20 58 6f 72 20 77 64 54 79 70 65 43 75 73 74 6f 6d 50 61 67 65 4e 75 6d 62 65 72 42 6f 74 74 6f 6d 29 29 29 } //1 + Chr(CLng((wdKeyNumeric9 Xor wdTypeCustomPageNumberBottom)))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}