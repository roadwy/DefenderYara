
rule TrojanDownloader_O97M_Donoff_DT{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DT,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 46 69 6c 74 65 72 5f 43 6c 65 61 72 28 4f 70 74 69 6f 6e 61 6c 20 73 74 72 69 6e 67 57 6b 73 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub AutoFilter_Clear(Optional stringWksName As String)
		$a_01_1 = {3d 20 43 4c 6e 67 28 4c 65 66 74 28 73 74 72 69 6e 67 54 69 6d 65 2c 20 69 6e 74 43 6f 6c 6f 6e 30 31 20 2d 20 31 29 29 } //1 = CLng(Left(stringTime, intColon01 - 1))
		$a_01_2 = {43 61 6c 6c 20 4f 70 74 69 6d 69 7a 65 5f 56 42 41 5f 50 65 72 66 6f 72 6d 61 6e 63 65 28 46 61 6c 73 65 2c 20 78 6c 41 75 74 6f 6d 61 74 69 63 29 } //1 Call Optimize_VBA_Performance(False, xlAutomatic)
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 22 46 6f 72 6d 20 69 73 20 6e 6f 74 20 76 69 73 69 62 6c 65 2e 20 54 68 65 20 63 6f 64 65 20 77 69 6c 6c 20 6e 6f 77 20 73 74 6f 70 2e 22 3a 20 45 6e 64 } //1 Debug.Print "Form is not visible. The code will now stop.": End
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_DT_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DT,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {73 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 43 6f 64 65 4e 61 6d 65 90 0c 02 00 49 66 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 20 3d 20 73 20 54 68 65 6e 20 6a 20 3d 20 6a 20 2d 20 31 90 0c 02 00 46 6f 72 20 69 20 3d 20 31 20 54 6f 20 33 32 90 0c 02 00 6a 20 3d 20 32 20 2a 20 6a 90 0c 02 00 4e 65 78 74 20 69 } //10
		$a_02_1 = {46 6f 72 20 90 1d 0f 00 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 90 1d 0f 00 29 90 0c 02 00 49 66 20 90 1d 0f 00 28 90 1d 0f 00 29 20 3d 20 90 1d 0f 00 28 90 1d 0f 00 29 20 54 68 65 6e 20 90 1d 0f 00 20 3d 20 90 1d 0f 00 20 2b 20 31 90 0c 02 00 4e 65 78 74 90 0c 02 00 49 66 20 90 1d 0f 00 20 3d 20 30 20 54 68 65 6e 90 0c 02 00 90 1d 0f 00 20 3d 20 90 1d 0f 00 20 2b 20 43 68 72 24 28 90 1d 0f 00 28 90 1d 0f 00 29 20 2d 20 90 0f 01 00 29 } //10
		$a_02_2 = {46 75 6e 63 74 69 6f 6e 20 66 75 6e 63 32 28 29 90 0c 02 00 66 6f 72 6d 31 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 } //1
		$a_00_3 = {46 75 6e 63 74 69 6f 6e 20 46 75 6e 63 5f 74 77 6f 28 29 } //1 Function Func_two()
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}