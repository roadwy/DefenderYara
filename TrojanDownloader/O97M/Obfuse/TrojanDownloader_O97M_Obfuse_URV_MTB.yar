
rule TrojanDownloader_O97M_Obfuse_URV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.URV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 28 75 6e 78 28 71 73 64 66 67 20 26 20 71 65 72 75 73 29 2c 20 31 29 } //1 Shell(unx(qsdfg & qerus), 1)
		$a_01_1 = {6f 6c 64 5f 63 68 61 72 20 3d 20 41 73 63 28 4d 69 64 28 74 65 78 74 2c 20 69 2c 20 31 29 29 } //1 old_char = Asc(Mid(text, i, 1))
		$a_01_2 = {6e 65 77 5f 63 68 61 72 20 3d 20 43 68 72 57 28 6f 6c 64 5f 63 68 61 72 20 2d 20 34 20 4d 6f 64 20 32 35 36 29 } //1 new_char = ChrW(old_char - 4 Mod 256)
		$a_01_3 = {71 73 64 66 67 20 3d 20 22 74 73 7b 69 76 77 6c 69 70 70 24 31 7b 6d 72 68 73 7b 77 78 7d 70 69 24 6c 6d 68 68 69 72 24 26 6a 79 72 67 78 6d 73 72 24 67 70 69 65 72 79 74 24 7f 6d 6a 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}