
rule Trojan_Win32_RemoteSysDisc_B_nltest{
	meta:
		description = "Trojan:Win32/RemoteSysDisc.B!nltest,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 6c 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {6e 00 6c 00 74 00 65 00 73 00 74 00 20 00 } //1 nltest 
		$a_00_2 = {20 00 2f 00 64 00 63 00 } //65535  /dc
		$a_00_3 = {2f 00 64 00 73 00 67 00 65 00 74 00 64 00 63 00 } //65535 /dsgetdc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*65535+(#a_00_3  & 1)*65535) >=1
 
}