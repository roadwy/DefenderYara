
rule TrojanDownloader_O97M_Dridex_YD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.YD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 28 6d 6a 28 22 24 22 2c 20 64 33 2c 20 22 58 22 2c 20 73 67 2c 20 6d 6a 28 22 3b 22 2c 20 6b 6b 2c 20 22 27 22 2c 20 64 32 2c 20 68 68 29 29 29 } //01 00  ExecuteExcel4Macro (mj("$", d3, "X", sg, mj(";", kk, "'", d2, hh)))
		$a_01_1 = {6e 6d 20 3d 20 76 6f 28 43 65 6c 6c 73 28 6a 2c 20 31 29 2c 20 49 6e 74 28 28 34 20 2d 20 31 20 2b 20 31 29 20 2a 20 52 6e 64 20 2b 20 31 29 29 } //01 00  nm = vo(Cells(j, 1), Int((4 - 1 + 1) * Rnd + 1))
		$a_01_2 = {77 77 20 3d 20 53 74 72 43 6f 6e 76 28 61 77 2c 20 76 62 46 72 6f 6d 55 6e 69 63 6f 64 65 29 } //00 00  ww = StrConv(aw, vbFromUnicode)
	condition:
		any of ($a_*)
 
}