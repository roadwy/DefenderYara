
rule TrojanDownloader_O97M_Netwire_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Netwire.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {78 20 3d 20 73 73 73 73 73 73 73 28 22 61 22 2c 20 90 02 0f 29 90 00 } //1
		$a_01_1 = {46 6f 72 20 6c 6f 6e 44 61 74 61 50 74 72 20 3d 20 31 20 54 6f 20 28 4c 65 6e 28 44 61 74 61 49 6e 29 20 2f 20 32 29 } //1 For lonDataPtr = 1 To (Len(DataIn) / 2)
		$a_01_2 = {69 6e 74 58 4f 72 56 61 6c 75 65 31 20 3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 44 61 74 61 49 6e 2c 20 28 32 20 2a 20 6c 6f 6e 44 61 74 61 50 74 72 29 20 2d 20 31 2c 20 32 29 29 29 } //1 intXOrValue1 = Val("&H" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))
		$a_01_3 = {69 6e 74 58 4f 72 56 61 6c 75 65 32 20 3d 20 41 73 63 28 4d 69 64 24 28 43 6f 64 65 4b 65 79 2c 20 28 28 6c 6f 6e 44 61 74 61 50 74 72 20 4d 6f 64 20 4c 65 6e 28 43 6f 64 65 4b 65 79 29 29 20 2b 20 31 29 2c 20 31 29 29 } //1 intXOrValue2 = Asc(Mid$(CodeKey, ((lonDataPtr Mod Len(CodeKey)) + 1), 1))
		$a_01_4 = {72 65 74 76 61 6c 20 3d 20 53 68 65 6c 6c 28 73 73 73 73 73 73 73 29 } //1 retval = Shell(sssssss)
		$a_01_5 = {73 74 72 44 61 74 61 4f 75 74 20 3d 20 73 74 72 44 61 74 61 4f 75 74 20 2b 20 43 68 72 28 69 6e 74 58 4f 72 56 61 6c 75 65 31 20 58 6f 72 20 69 6e 74 58 4f 72 56 61 6c 75 65 32 29 } //1 strDataOut = strDataOut + Chr(intXOrValue1 Xor intXOrValue2)
		$a_03_6 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 02 03 44 69 6d 20 90 02 0f 20 41 73 20 53 74 72 69 6e 67 90 02 03 90 1b 01 20 3d 20 90 1b 01 20 2b 20 22 30 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}