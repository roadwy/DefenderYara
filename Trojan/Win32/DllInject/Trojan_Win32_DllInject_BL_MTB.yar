
rule Trojan_Win32_DllInject_BL_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 73 67 64 66 4b 69 75 79 74 } //02 00  SsgdfKiuyt
		$a_01_1 = {44 65 67 72 68 66 4c 67 6a 66 68 64 66 } //02 00  DegrhfLgjfhdf
		$a_01_2 = {4e 72 68 74 6a 79 4a 6b 79 6a 74 68 } //01 00  NrhtjyJkyjth
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}