
rule TrojanDownloader_O97M_Remcos_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 70 6f 77 65 22 20 2b 20 22 72 73 22 20 2b 20 52 61 6e 67 65 28 22 46 31 30 30 22 29 2e 56 61 6c 75 65 } //1 "powe" + "rs" + Range("F100").Value
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 56 4d 57 59 42 28 29 29 } //1 CreateObject(VMWYB())
		$a_01_2 = {67 67 67 2e 45 78 65 63 4d 65 74 68 6f 64 5f 28 48 42 79 6e 28 29 2c 20 66 38 64 66 30 30 29 } //1 ggg.ExecMethod_(HByn(), f8df00)
		$a_01_3 = {22 43 22 20 2b 20 41 63 74 69 76 65 53 68 65 65 74 2e 50 61 67 65 53 65 74 75 70 2e 4c 65 66 74 46 6f 6f 74 65 72 20 2b 20 66 6a 6a 64 66 28 29 } //1 "C" + ActiveSheet.PageSetup.LeftFooter + fjjdf()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Remcos_RVA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Remcos.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 41 63 74 69 76 65 53 68 65 65 74 2e 50 61 67 65 53 65 74 75 70 2e 43 65 6e 74 65 72 48 65 61 64 65 72 29 } //1 CreateObject(ActiveSheet.PageSetup.CenterHeader)
		$a_01_1 = {5a 49 41 52 62 28 29 2e 45 78 65 63 20 6b 6f 67 48 33 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_2 = {46 6f 72 20 45 61 63 68 20 5a 76 46 44 6c 77 78 20 49 6e 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 } //1 For Each ZvFDlwx In ActiveWorkbook.BuiltinDocumentProperties
		$a_01_3 = {3d 20 22 70 22 20 2b 20 41 63 74 69 76 65 53 68 65 65 74 2e 50 61 67 65 53 65 74 75 70 2e 43 65 6e 74 65 72 46 6f 6f 74 65 72 } //1 = "p" + ActiveSheet.PageSetup.CenterFooter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}