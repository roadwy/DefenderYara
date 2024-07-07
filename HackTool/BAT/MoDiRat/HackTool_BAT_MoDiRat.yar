
rule HackTool_BAT_MoDiRat{
	meta:
		description = "HackTool:BAT/MoDiRat,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 44 69 20 52 41 54 } //1 MoDi RAT
		$a_01_1 = {61 75 64 69 6f 66 72 6d 00 } //1
		$a_01_2 = {4b 79 6c 6f 67 73 00 } //1
		$a_01_3 = {64 65 6d 61 72 72 61 67 65 00 } //1 敤慭牲条e
		$a_01_4 = {77 65 62 63 61 6d 5f 4c 6f 61 64 } //1 webcam_Load
		$a_01_5 = {53 70 65 61 6b 46 6f 72 6d 5f 4c 6f 61 64 } //1 SpeakForm_Load
		$a_01_6 = {4d 00 6f 00 44 00 69 00 20 00 52 00 41 00 54 00 } //1 MoDi RAT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}