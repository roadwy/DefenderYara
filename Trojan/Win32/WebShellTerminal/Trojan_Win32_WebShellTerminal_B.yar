
rule Trojan_Win32_WebShellTerminal_B{
	meta:
		description = "Trojan:Win32/WebShellTerminal.B,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //10 cmd
		$a_00_1 = {26 00 63 00 64 00 26 00 65 00 63 00 68 00 6f 00 } //1 &cd&echo
		$a_00_2 = {26 00 63 00 64 00 26 00 26 00 65 00 63 00 68 00 6f 00 } //1 &cd&&echo
		$a_02_3 = {65 00 63 00 68 00 6f 00 [0-02] 5b 00 [0-06] 5d 00 [0-02] 26 00 [0-02] 63 00 64 00 [0-02] 26 00 [0-02] 65 00 63 00 68 00 6f 00 [0-02] 5b 00 [0-06] 5d 00 } //1
		$a_00_4 = {44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 3a 00 20 00 26 00 26 00 63 00 64 00 26 00 26 00 65 00 63 00 68 00 6f 00 } //-50 Directory: &&cd&&echo
		$a_00_5 = {57 00 41 00 52 00 50 00 } //-50 WARP
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*-50+(#a_00_5  & 1)*-50) >=11
 
}