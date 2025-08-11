
rule Trojan_Win32_FileFix_D_MTB{
	meta:
		description = "Trojan:Win32/FileFix.D!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {2e 00 64 00 6f 00 63 00 78 00 } //1 .docx
		$a_02_2 = {2d 00 63 00 20 00 70 00 69 00 6e 00 67 00 [0-50] 23 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}