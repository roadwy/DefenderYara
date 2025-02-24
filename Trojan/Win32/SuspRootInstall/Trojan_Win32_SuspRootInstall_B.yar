
rule Trojan_Win32_SuspRootInstall_B{
	meta:
		description = "Trojan:Win32/SuspRootInstall.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 20 62 79 70 61 73 73 } //powershell -ex bypass  1
		$a_80_1 = {49 6d 70 6f 72 74 2d 43 65 72 74 69 66 69 63 61 74 65 } //Import-Certificate  1
		$a_02_2 = {2d 00 46 00 69 00 6c 00 65 00 50 00 61 00 74 00 68 00 [0-20] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 } //1
		$a_02_3 = {2d 46 69 6c 65 50 61 74 68 [0-20] 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}