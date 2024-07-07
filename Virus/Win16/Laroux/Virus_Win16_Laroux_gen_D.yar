
rule Virus_Win16_Laroux_gen_D{
	meta:
		description = "Virus:Win16/Laroux.gen!D,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 4d 6f 64 75 6c 65 73 2e 43 6f 75 6e 74 20 3e 20 30 20 54 68 65 6e 20 77 20 3d 20 31 20 45 6c 73 65 20 77 20 3d 20 30 } //1 If ActiveWorkbook.Modules.Count > 0 Then w = 1 Else w = 0
		$a_01_1 = {22 29 2e 43 6f 70 79 20 62 65 66 6f 72 65 3a 3d 57 6f 72 6b 62 6f 6f 6b 73 28 6e 34 24 29 2e 53 68 65 65 74 73 28 31 29 } //1 ").Copy before:=Workbooks(n4$).Sheets(1)
		$a_01_2 = {57 6f 72 6b 62 6f 6f 6b 73 28 6e 65 77 6e 61 6d 65 24 29 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 2f 22 20 26 20 22 } //1 Workbooks(newname$).SaveAs FileName:=Application.StartupPath & "/" & "
		$a_01_3 = {77 68 69 63 68 66 69 6c 65 20 3d 20 70 20 2b 20 77 20 2a 20 31 30 } //1 whichfile = p + w * 10
		$a_01_4 = {22 29 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 } //1 ").Visible = False
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}