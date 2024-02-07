
rule TrojanDownloader_O97M_Dridex_AJS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.AJS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 5a 70 72 69 6e 74 5f 6f 6e 65 5f 70 61 67 65 28 29 } //01 00  Sub Zprint_one_page()
		$a_01_1 = {52 6f 4c 6f 20 3d 20 53 70 6c 69 74 28 52 54 72 69 6d 28 6c 61 73 74 5f 70 61 79 5f 6a 61 6e 29 2c 20 4f 6b 5f 50 72 69 6e 74 31 28 22 29 22 29 29 } //01 00  RoLo = Split(RTrim(last_pay_jan), Ok_Print1(")"))
		$a_01_2 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 4e 65 78 74 5f 50 61 67 65 5f 63 61 6c 63 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f } //01 00  Private Declare PtrSafe Function Next_Page_calc Lib "urlmon" _
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 66 69 6e 64 44 61 74 65 28 64 65 70 6f 73 69 74 5f 61 28 53 70 6c 69 74 28 52 6f 4c 6f 28 30 29 2c 20 4f 6b 5f 50 72 69 6e 74 31 28 22 44 22 29 29 29 29 } //01 00  Debug.Print findDate(deposit_a(Split(RoLo(0), Ok_Print1("D"))))
		$a_01_4 = {53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 33 2c 20 31 29 2e 4e 61 6d 65 20 3d 20 22 43 41 52 47 4f 5f 22 20 26 20 22 73 22 } //01 00  Sheets(1).Cells(3, 1).Name = "CARGO_" & "s"
		$a_01_5 = {66 75 72 6d 69 73 20 3d 20 53 70 6c 69 74 28 52 6f 4c 6f 28 31 29 2c 20 4f 6b 5f 50 72 69 6e 74 31 28 22 2b 22 29 29 } //01 00  furmis = Split(RoLo(1), Ok_Print1("+"))
		$a_03_6 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 0c 02 00 53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 33 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 3d 22 20 26 20 66 75 72 6d 69 73 28 41 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}