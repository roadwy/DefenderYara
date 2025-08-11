
rule Trojan_Win32_PShellObf_SA{
	meta:
		description = "Trojan:Win32/PShellObf.SA,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_02_1 = {5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 31 00 30 00 35 00 29 00 [0-10] 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 31 00 30 00 31 00 29 00 [0-10] 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 31 00 32 00 30 00 29 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}