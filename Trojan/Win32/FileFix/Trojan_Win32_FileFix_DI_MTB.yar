
rule Trojan_Win32_FileFix_DI_MTB{
	meta:
		description = "Trojan:Win32/FileFix.DI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_02_1 = {2d 00 63 00 20 00 70 00 69 00 6e 00 67 00 [0-50] 23 00 } //10
		$a_00_2 = {2e 00 64 00 6f 00 63 00 78 00 } //1 .docx
		$a_00_3 = {2e 00 70 00 64 00 66 00 } //1 .pdf
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=111
 
}