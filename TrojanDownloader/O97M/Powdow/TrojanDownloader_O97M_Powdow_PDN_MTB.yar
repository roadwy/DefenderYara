
rule TrojanDownloader_O97M_Powdow_PDN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 45 72 72 6f 72 20 50 6c 65 61 73 65 20 44 6f 77 6e 6c 6f 61 64 20 66 69 6c 65 20 61 67 61 69 6e 22 } //1 MsgBox "Error Please Download file again"
		$a_03_1 = {6f 62 6a 53 68 65 6c 6c 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 73 68 65 6c 6c 65 78 65 63 75 74 65 20 6c 75 6c 2e 6c 6f 6c 2c 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f [0-2f] 22 2c } //1
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 28 22 6e 22 20 2b 20 22 65 22 20 2b 20 22 70 22 20 2b 20 22 6f 22 29 2c 20 30 } //1 StrReverse("n" + "e" + "p" + "o"), 0
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}