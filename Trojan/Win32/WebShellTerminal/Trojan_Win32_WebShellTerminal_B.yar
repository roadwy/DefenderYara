
rule Trojan_Win32_WebShellTerminal_B{
	meta:
		description = "Trojan:Win32/WebShellTerminal.B,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //0a 00  cmd
		$a_00_1 = {2f 00 63 00 20 00 63 00 64 00 } //01 00  /c cd
		$a_00_2 = {26 00 63 00 64 00 26 00 65 00 63 00 68 00 6f 00 } //01 00  &cd&echo
		$a_00_3 = {26 00 63 00 64 00 26 00 26 00 65 00 63 00 68 00 6f 00 } //00 00  &cd&&echo
	condition:
		any of ($a_*)
 
}