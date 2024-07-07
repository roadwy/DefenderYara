
rule HackTool_Win32_Mikatz{
	meta:
		description = "HackTool:Win32/Mikatz,SIGNATURE_TYPE_PEHSTR,2c 01 2c 01 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a } //100 powershell_reflective_mimikatz
		$a_01_1 = {70 6f 77 65 72 6b 61 74 7a 2e 64 6c 6c } //100 powerkatz.dll
		$a_01_2 = {4b 00 49 00 57 00 49 00 5f 00 4d 00 53 00 56 00 31 00 5f 00 30 00 5f 00 43 00 52 00 45 00 44 00 45 00 4e 00 54 00 49 00 41 00 4c 00 53 00 } //100 KIWI_MSV1_0_CREDENTIALS
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=300
 
}