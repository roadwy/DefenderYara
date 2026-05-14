
rule DoS_Win32_SDeleteAbuse_CA_dha{
	meta:
		description = "DoS:Win32/SDeleteAbuse.CA!dha,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-20] 3a 00 [0-04] 2a 00 } //1
		$a_01_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 65 00 78 00 2a 00 } //1 taskkill /f /im ex*
		$a_01_2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2d 00 73 00 20 00 2d 00 66 00 20 00 2d 00 74 00 20 00 36 00 36 00 36 00 } //1 shutdown -s -f -t 666
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}