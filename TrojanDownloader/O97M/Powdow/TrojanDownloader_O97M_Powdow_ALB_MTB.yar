
rule TrojanDownloader_O97M_Powdow_ALB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 65 61 73 79 76 69 65 74 74 72 61 76 65 6c 2e 76 6e 2f 76 65 6e 64 6f 72 2f 73 65 6c 64 2f 30 41 33 2f 53 70 65 63 69 66 69 63 61 74 69 6f 6e 73 5f 44 65 74 61 69 6c 73 5f 32 30 32 33 30 30 5f 52 46 51 22 20 26 20 52 65 70 6c 61 63 65 28 22 2e 67 6b 34 64 78 65 22 2c 20 22 67 6b 34 64 22 2c 20 22 65 22 29 } //1 Start-BitsTransfer -Source htt`p://easyviettravel.vn/vendor/seld/0A3/Specifications_Details_202300_RFQ" & Replace(".gk4dxe", "gk4d", "e")
		$a_01_1 = {74 6f 6f 61 62 6f 76 65 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 66 72 6f 6e 74 63 68 65 63 6b 2e 62 61 74 22 } //1 tooabove = "C:\Users\Public\Documents\frontcheck.bat"
		$a_01_2 = {50 72 69 6e 74 20 23 6f 66 66 69 63 69 61 6c 68 65 61 72 } //1 Print #officialhear
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}