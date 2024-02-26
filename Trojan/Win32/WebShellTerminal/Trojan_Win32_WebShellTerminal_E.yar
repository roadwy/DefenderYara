
rule Trojan_Win32_WebShellTerminal_E{
	meta:
		description = "Trojan:Win32/WebShellTerminal.E,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //0a 00  cmd
		$a_00_1 = {2f 00 63 00 20 00 70 00 75 00 73 00 68 00 64 00 } //0a 00  /c pushd
		$a_02_2 = {26 00 65 00 63 00 68 00 6f 00 90 01 02 5b 00 90 00 } //ce ff 
		$a_00_3 = {26 00 63 00 64 00 26 00 65 00 63 00 68 00 6f 00 } //00 00  &cd&echo
	condition:
		any of ($a_*)
 
}