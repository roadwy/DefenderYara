
rule Trojan_Win32_BITSAbuse_D{
	meta:
		description = "Trojan:Win32/BITSAbuse.D,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 [0-20] 2f 00 63 00 } //1
		$a_02_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-10] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //1
		$a_00_2 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 } //1 certutil -decode
		$a_02_3 = {73 00 74 00 61 00 72 00 74 00 [0-f0] 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}