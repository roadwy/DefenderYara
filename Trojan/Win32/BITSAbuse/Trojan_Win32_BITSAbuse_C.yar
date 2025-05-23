
rule Trojan_Win32_BITSAbuse_C{
	meta:
		description = "Trojan:Win32/BITSAbuse.C,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 [0-20] 2f 00 63 00 } //10
		$a_02_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-10] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //10
		$a_02_2 = {68 00 74 00 74 00 70 00 [0-f0] 2e 00 65 00 78 00 65 00 } //10
		$a_02_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-f0] 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 } //1
		$a_02_4 = {73 00 74 00 61 00 72 00 74 00 [0-f0] 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=31
 
}