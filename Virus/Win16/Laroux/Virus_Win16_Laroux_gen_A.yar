
rule Virus_Win16_Laroux_gen_A{
	meta:
		description = "Virus:Win16/Laroux.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 53 74 61 72 74 55 70 2e 78 6c 73 22 29 2e 53 68 65 65 74 73 28 22 53 74 61 72 74 55 70 22 29 2e 43 6f 70 79 20 62 65 66 6f 72 65 3a 3d 57 6f 72 6b 73 68 65 65 74 73 28 31 29 } //01 00  Workbooks("StartUp.xls").Sheets("StartUp").Copy before:=Worksheets(1)
		$a_00_1 = {53 75 62 20 79 63 6f 70 28 29 } //01 00  Sub ycop()
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 53 68 65 65 74 41 63 74 69 76 61 74 65 20 3d 20 22 53 74 61 72 74 55 70 2e 78 6c 73 21 79 63 6f 70 22 } //00 00  Application.OnSheetActivate = "StartUp.xls!ycop"
	condition:
		any of ($a_*)
 
}