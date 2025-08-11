
rule Trojan_Win32_MsSenseComponentTamper_D{
	meta:
		description = "Trojan:Win32/MsSenseComponentTamper.D,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 00 63 00 61 00 63 00 6c 00 73 00 } //1 icacls
		$a_00_1 = {6d 00 73 00 73 00 65 00 6e 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 mssense.dll
		$a_00_2 = {20 00 2f 00 64 00 65 00 6e 00 79 00 20 00 } //1  /deny 
		$a_00_3 = {20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 } //1  everyone:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}