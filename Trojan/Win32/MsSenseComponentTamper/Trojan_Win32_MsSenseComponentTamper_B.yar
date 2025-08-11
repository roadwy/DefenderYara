
rule Trojan_Win32_MsSenseComponentTamper_B{
	meta:
		description = "Trojan:Win32/MsSenseComponentTamper.B,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 00 63 00 61 00 63 00 6c 00 73 00 } //1 icacls
		$a_00_1 = {4d 00 73 00 53 00 65 00 6e 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 MsSense.dll
		$a_00_2 = {20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 } //1  /grant 
		$a_00_3 = {3a 00 46 00 } //1 :F
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}