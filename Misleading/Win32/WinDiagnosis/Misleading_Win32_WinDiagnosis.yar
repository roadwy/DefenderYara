
rule Misleading_Win32_WinDiagnosis{
	meta:
		description = "Misleading:Win32/WinDiagnosis,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 75 6e 6a 6b 64 65 66 72 61 67 } //01 00  runjkdefrag
		$a_00_1 = {73 74 6f 70 6a 6b 64 65 66 72 61 67 } //01 00  stopjkdefrag
		$a_00_2 = {61 76 61 73 74 } //02 00  avast
		$a_00_3 = {61 6c 65 72 74 64 69 61 6c 6f 67 } //0a 00  alertdialog
		$a_01_4 = {66 65 74 63 68 44 61 74 61 49 73 73 75 65 73 40 66 69 6c 65 73 79 73 74 65 6d 40 6f 70 74 69 } //00 00  fetchDataIssues@filesystem@opti
		$a_00_5 = {5f 0f 00 00 10 00 5c 67 65 65 } //6b 68 
	condition:
		any of ($a_*)
 
}