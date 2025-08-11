
rule Trojan_Win32_SuspRootInstall_A{
	meta:
		description = "Trojan:Win32/SuspRootInstall.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {26 20 63 65 72 74 75 74 69 6c 2e 65 78 65 } //& certutil.exe  1
		$a_80_1 = {2d 61 64 64 73 74 6f 72 65 20 72 6f 6f 74 } //-addstore root  1
		$a_80_2 = {5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c } //\windows\temp\  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}