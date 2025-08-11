
rule Trojan_Win32_CopyRemot_B{
	meta:
		description = "Trojan:Win32/CopyRemot.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 62 00 } //1 cmd /c copy /b
		$a_02_1 = {2e 00 74 00 6d 00 70 00 20 00 2b 00 [0-3c] 2e 00 74 00 6d 00 70 00 20 00 2b 00 [0-3c] 2e 00 74 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}