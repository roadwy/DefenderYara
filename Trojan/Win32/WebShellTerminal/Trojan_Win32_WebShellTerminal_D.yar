
rule Trojan_Win32_WebShellTerminal_D{
	meta:
		description = "Trojan:Win32/WebShellTerminal.D,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //10 cmd
		$a_02_1 = {26 00 65 00 63 00 68 00 6f 00 [0-02] 5b 00 ?? ?? 5d 00 26 00 63 00 64 00 26 00 65 00 63 00 68 00 6f 00 [0-02] 5b 00 ?? ?? 5d 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}