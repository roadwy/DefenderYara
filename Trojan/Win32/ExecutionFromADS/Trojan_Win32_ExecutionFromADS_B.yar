
rule Trojan_Win32_ExecutionFromADS_B{
	meta:
		description = "Trojan:Win32/ExecutionFromADS.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {26 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 20 3c } //& powershell.exe - <  1
		$a_02_1 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-90] 74 00 78 00 74 00 3a 00 } //1
		$a_02_2 = {5c 74 65 6d 70 5c [0-90] 74 78 74 3a } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}