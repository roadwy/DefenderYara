
rule Virus_Win16_Laroux_gen_C{
	meta:
		description = "Virus:Win16/Laroux.gen!C,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {2e 78 6c 73 21 [0-02] 63 6f 70 } //10
		$a_00_1 = {2e 78 6c 73 21 65 73 63 61 70 65 } //10 .xls!escape
		$a_00_2 = {41 63 74 69 76 65 57 69 6e 64 6f 77 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 } //1 ActiveWindow.Visible = False
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 44 69 73 70 6c 61 79 41 6c 65 72 74 73 20 3d 20 46 61 6c 73 65 } //1 Application.DisplayAlerts = False
		$a_00_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 46 61 6c 73 65 } //1 Application.ScreenUpdating = False
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}