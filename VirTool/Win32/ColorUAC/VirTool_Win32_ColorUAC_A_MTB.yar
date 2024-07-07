
rule VirTool_Win32_ColorUAC_A_MTB{
	meta:
		description = "VirTool:Win32/ColorUAC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 3a } //1 Elevation:Administrator!new:
		$a_81_1 = {43 6f 47 65 74 4f 62 6a 65 63 74 } //1 CoGetObject
		$a_81_2 = {43 6f 49 6e 69 74 69 61 6c 69 7a 65 45 78 } //1 CoInitializeEx
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 43 4d 5c 43 61 6c 69 62 72 61 74 69 6f 6e } //1 Software\Microsoft\Windows NT\CurrentVersion\ICM\Calibration
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}