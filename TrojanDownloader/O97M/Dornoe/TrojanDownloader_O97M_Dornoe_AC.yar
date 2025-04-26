
rule TrojanDownloader_O97M_Dornoe_AC{
	meta:
		description = "TrojanDownloader:O97M/Dornoe.AC,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 43 6f 72 65 72 63 74 20 3d 20 52 65 6d 61 72 6b 5f 31 20 2b 20 69 30 32 20 2b 20 43 6f 70 79 43 68 65 63 6b 65 72 20 2b 20 69 30 34 20 2b 20 52 65 6d 73 73 20 2b 20 4c 6f 67 6f 46 69 72 6d 20 2b 20 69 30 37 20 2b 20 69 30 38 } //1 AutoCorerct = Remark_1 + i02 + CopyChecker + i04 + Remss + LogoFirm + i07 + i08
		$a_01_1 = {52 65 6d 61 72 6b 5f 31 20 3d 20 43 65 6c 6c 73 28 35 2c 20 31 29 2e 54 65 78 74 } //1 Remark_1 = Cells(5, 1).Text
		$a_01_2 = {3d 20 53 68 65 6c 6c 23 28 57 71 41 2c 20 78 6c 4c 6f 6f 6b 46 6f 72 42 6c 61 6e 6b 73 29 } //1 = Shell#(WqA, xlLookForBlanks)
		$a_01_3 = {52 65 70 6c 61 63 65 28 52 65 70 6c 61 63 65 28 52 65 70 6c 61 63 65 28 63 68 65 63 6b 2c 20 22 23 2e 61 22 2c 20 22 77 22 29 2c 20 22 2c 2e 79 22 2c 20 22 65 22 29 2c 20 22 2b 2e 5a 22 2c 20 22 63 22 29 } //1 Replace(Replace(Replace(check, "#.a", "w"), ",.y", "e"), "+.Z", "c")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}