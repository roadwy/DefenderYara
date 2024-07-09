
rule TrojanDownloader_O97M_Donoff_PS{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PS,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 20 28 [0-07] 29 } //1
		$a_02_1 = {47 6f 54 6f 20 [0-1a] 20 45 78 69 74 20 53 75 62 } //1
		$a_00_2 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Sub Workbook_Open()
		$a_00_3 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 63 61 6c 63 73 68 65 65 74 22 29 2e 52 61 6e 67 65 28 } //1 ThisWorkbook.Sheets("calcsheet").Range(
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}