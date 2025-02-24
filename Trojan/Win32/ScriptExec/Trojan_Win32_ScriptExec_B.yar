
rule Trojan_Win32_ScriptExec_B{
	meta:
		description = "Trojan:Win32/ScriptExec.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 2e 65 78 65 } //wmic.exe  1
		$a_80_1 = {6f 73 20 67 65 74 } //os get  1
		$a_02_2 = {2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 [0-04] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-80] 2e 00 78 00 73 00 6c 00 } //1
		$a_02_3 = {2f 66 6f 72 6d 61 74 3a [0-04] 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-80] 2e 78 73 6c } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}