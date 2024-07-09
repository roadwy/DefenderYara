
rule Trojan_Win32_PShellDlr_SA{
	meta:
		description = "Trojan:Win32/PShellDlr.SA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  1
		$a_80_1 = {6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 } //new-object net.webclient  1
		$a_02_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-02] 68 00 74 00 74 00 70 00 [0-01] 3a 00 2f 00 2f 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}