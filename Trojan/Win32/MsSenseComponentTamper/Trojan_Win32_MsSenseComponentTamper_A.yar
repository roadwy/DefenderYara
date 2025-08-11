
rule Trojan_Win32_MsSenseComponentTamper_A{
	meta:
		description = "Trojan:Win32/MsSenseComponentTamper.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 6b 00 65 00 6f 00 77 00 6e 00 } //1 takeown
		$a_00_1 = {20 00 2f 00 66 00 20 00 } //1  /f 
		$a_00_2 = {6d 00 73 00 73 00 65 00 6e 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 mssense.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}