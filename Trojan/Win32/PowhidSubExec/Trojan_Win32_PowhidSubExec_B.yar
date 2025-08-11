
rule Trojan_Win32_PowhidSubExec_B{
	meta:
		description = "Trojan:Win32/PowhidSubExec.B,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_02_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 [0-3c] 24 00 } //1
		$a_00_2 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 } //1 appdata
		$a_02_3 = {2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 [0-3c] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}