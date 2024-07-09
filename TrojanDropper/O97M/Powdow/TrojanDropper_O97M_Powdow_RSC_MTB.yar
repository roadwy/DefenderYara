
rule TrojanDropper_O97M_Powdow_RSC_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.RSC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Sub Workbook_Open()
		$a_03_1 = {6d 73 62 75 69 6c 64 2e 65 78 65 20 [0-04] 32 30 34 2e 34 38 2e 32 31 2e 32 33 36 [0-02] 77 65 62 64 61 76 [0-02] 6d 73 62 75 69 6c 64 2e 78 6d 6c } //1
		$a_03_2 = {54 61 73 6b 49 44 20 3d 20 53 68 65 6c 6c 28 50 72 6f 67 72 61 6d 2c 20 ?? 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}