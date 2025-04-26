
rule Misleading_Win32_Softeallion{
	meta:
		description = "Misleading:Win32/Softeallion,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 77 69 73 65 66 69 78 65 72 5c 73 76 6e } //1 E:\wisefixer\svn
		$a_01_1 = {4d 00 55 00 54 00 45 00 58 00 5f 00 57 00 49 00 53 00 45 00 5f 00 46 00 49 00 58 00 45 00 52 00 5f 00 45 00 58 00 43 00 4c 00 55 00 44 00 45 00 5f 00 4f 00 42 00 4a 00 45 00 43 00 54 00 5f 00 4c 00 55 00 43 00 4b 00 } //1 MUTEX_WISE_FIXER_EXCLUDE_OBJECT_LUCK
		$a_01_2 = {49 00 44 00 53 00 5f 00 53 00 54 00 41 00 52 00 54 00 5f 00 53 00 43 00 41 00 4e 00 5f 00 52 00 45 00 53 00 55 00 4c 00 54 00 5f 00 54 00 41 00 42 00 5f 00 4a 00 55 00 4e 00 4b 00 46 00 49 00 4c 00 45 00 } //1 IDS_START_SCAN_RESULT_TAB_JUNKFILE
		$a_01_3 = {53 00 63 00 61 00 6e 00 4a 00 75 00 6e 00 6b 00 46 00 69 00 6c 00 65 00 45 00 72 00 72 00 6f 00 72 00 43 00 6f 00 75 00 6e 00 74 00 } //1 ScanJunkFileErrorCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}