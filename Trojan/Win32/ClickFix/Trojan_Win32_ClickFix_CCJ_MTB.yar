
rule Trojan_Win32_ClickFix_CCJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 54 00 43 00 50 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 System.Net.Sockets.TCPClient
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}