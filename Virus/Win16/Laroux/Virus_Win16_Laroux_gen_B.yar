
rule Virus_Win16_Laroux_gen_B{
	meta:
		description = "Virus:Win16/Laroux.gen!B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 4d 45 4d 4f 31 2e 58 4c 53 22 29 2e 53 68 65 65 74 73 28 22 4b 6e 69 67 68 74 22 29 2e 43 6f 70 79 20 62 65 66 6f 72 65 3a 3d 57 6f 72 6b 62 6f 6f 6b 73 28 6e 34 24 29 2e 53 68 65 65 74 73 28 31 29 } //01 00  Workbooks("MEMO1.XLS").Sheets("Knight").Copy before:=Workbooks(n4$).Sheets(1)
		$a_00_1 = {53 75 62 20 63 68 65 63 6b 5f 66 69 6c 65 73 28 29 } //01 00  Sub check_files()
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 53 68 65 65 74 41 63 74 69 76 61 74 65 20 3d 20 22 4d 45 4d 4f 31 2e 78 6c 73 21 63 68 65 63 6b 5f 66 69 6c 65 73 22 } //00 00  Application.OnSheetActivate = "MEMO1.xls!check_files"
	condition:
		any of ($a_*)
 
}