
rule Trojan_O97M_Clayslide_A{
	meta:
		description = "Trojan:O97M/Clayslide.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e } //1 Private Sub Workbook_Open
		$a_00_1 = {43 61 6c 6c 20 66 69 72 65 65 79 65 5f 49 6e 69 74 } //1 Call fireeye_Init
		$a_00_2 = {53 65 74 20 77 73 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 } //1 Set wss = CreateObject("WS
		$a_00_3 = {77 73 73 2e 52 75 6e 20 63 6d } //1 wss.Run cm
		$a_00_4 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 } //1 ActiveWorkbook.Worksheets(1).Visible = False
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}