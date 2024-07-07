
rule Trojan_Win32_RemoteSysDisc_E_adfind{
	meta:
		description = "Trojan:Win32/RemoteSysDisc.E!adfind,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {61 00 64 00 66 00 69 00 6e 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {20 00 61 00 64 00 66 00 69 00 6e 00 64 00 } //1  adfind
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}