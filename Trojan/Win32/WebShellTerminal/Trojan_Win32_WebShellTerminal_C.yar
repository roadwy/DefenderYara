
rule Trojan_Win32_WebShellTerminal_C{
	meta:
		description = "Trojan:Win32/WebShellTerminal.C,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //0a 00 
		$a_00_1 = {2f 00 63 00 20 00 63 00 64 00 20 00 2f 00 64 00 } //ce ff  /c cd /d
		$a_00_2 = {2e 00 63 00 6d 00 64 00 72 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //ce ff  .cmdret.dat
		$a_00_3 = {73 00 76 00 6e 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 } //ce ff  svn update
		$a_00_4 = {26 00 26 00 } //00 00  &&
	condition:
		any of ($a_*)
 
}