
rule TrojanDownloader_O97M_Dridex_AJT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.AJT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 20 28 22 43 41 52 47 4f 5f 22 20 26 20 22 73 22 29 } //1 Run ("CARGO_" & "s")
		$a_01_1 = {4e 65 78 74 5f 50 61 67 65 5f 63 61 6c 63 20 30 2c 20 66 69 6e 64 44 61 74 65 28 64 65 70 6f 73 69 74 5f 61 28 53 70 6c 69 74 28 52 6f 4c 6f 28 30 29 2c 20 4f 6b 5f 50 72 69 6e 74 31 28 22 44 22 29 29 29 29 2c 20 41 5f 6d 69 6e 5f 31 20 26 20 22 5c 22 20 26 20 76 65 67 61 2c 20 30 2c 20 30 } //1 Next_Page_calc 0, findDate(deposit_a(Split(RoLo(0), Ok_Print1("D")))), A_min_1 & "\" & vega, 0, 0
		$a_01_2 = {6f 72 64 65 72 5f 74 6f 5f 6f 72 64 65 72 20 3d 20 53 68 65 65 74 73 28 31 29 2e 52 61 6e 67 65 28 22 42 31 3a 42 35 22 29 2e 53 70 65 63 69 61 6c 43 65 6c 6c 73 28 78 6c 43 65 6c 6c 54 79 70 65 43 6f 6e 73 74 61 6e 74 73 29 } //1 order_to_order = Sheets(1).Range("B1:B5").SpecialCells(xlCellTypeConstants)
		$a_01_3 = {52 61 6e 64 6f 6d 69 7a 65 3a 20 64 66 20 3d 20 32 20 2d 20 31 3a 20 64 65 70 6f 73 69 74 5f 61 20 3d 20 6e 69 6d 6f 28 49 6e 74 28 28 55 42 6f 75 6e 64 28 6e 69 6d 6f 29 20 2b 20 64 66 29 20 2a 20 52 6e 64 29 29 } //1 Randomize: df = 2 - 1: deposit_a = nimo(Int((UBound(nimo) + df) * Rnd))
		$a_01_4 = {6c 61 73 74 5f 70 61 79 5f 6a 61 6e 20 3d 20 52 54 72 69 6d 28 72 65 7a 7a 7a 75 6c 74 29 } //1 last_pay_jan = RTrim(rezzzult)
		$a_01_5 = {72 65 7a 7a 7a 75 6c 74 20 3d 20 72 65 7a 7a 7a 75 6c 74 20 26 20 74 65 72 6d 73 41 6e 64 28 57 68 61 74 5f 65 61 73 74 2c 20 75 29 20 26 20 74 65 72 6d 73 41 6e 64 28 6f 76 65 72 64 75 65 5f 32 30 32 31 2c 20 75 29 20 26 20 74 65 72 6d 73 41 6e 64 28 4f 6e 6c 79 5f 66 6f 72 5f 70 72 69 6e 74 2c 20 75 29 } //1 rezzzult = rezzzult & termsAnd(What_east, u) & termsAnd(overdue_2021, u) & termsAnd(Only_for_print, u)
		$a_01_6 = {4f 6b 5f 50 72 69 6e 74 31 20 3d 20 52 65 70 6c 61 63 65 28 53 74 72 69 6e 67 28 34 2c 20 22 5a 22 29 2c 20 22 5a 22 2c 20 64 66 29 } //1 Ok_Print1 = Replace(String(4, "Z"), "Z", df)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}