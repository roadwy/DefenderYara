
rule Virus_Win16_Laroux_A{
	meta:
		description = "Virus:Win16/Laroux.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 20 26 20 22 5c 58 4c 53 54 41 52 54 5c 6d 79 70 65 72 73 6f 6e 65 6c 2e 78 6c 73 22 } //1 ThisWorkbook.SaveAs Filename:=Application.Path & "\XLSTART\mypersonel.xls"
		$a_00_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 43 6f 70 79 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 6d 79 70 65 72 73 6f 6e 6e 65 6c 2e 78 6c 73 22 } //1 ThisWorkbook.SaveCopyAs Filename:=Application.StartupPath & "\mypersonnel.xls"
		$a_00_2 = {4b 69 6c 6c 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 52 65 70 6c 61 63 65 28 } //1 Kill ThisWorkbook.Path & "\" & Replace(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}