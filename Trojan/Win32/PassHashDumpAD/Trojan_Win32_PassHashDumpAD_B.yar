
rule Trojan_Win32_PassHashDumpAD_B{
	meta:
		description = "Trojan:Win32/PassHashDumpAD.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2e 00 65 00 78 00 65 00 20 00 2f 00 69 00 20 00 22 00 63 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 22 00 20 00 5c 00 5c 00 [0-ff] 5c 00 73 00 79 00 73 00 76 00 6f 00 6c 00 5c 00 [0-ff] 5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}