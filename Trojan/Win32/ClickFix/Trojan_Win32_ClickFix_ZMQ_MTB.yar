
rule Trojan_Win32_ClickFix_ZMQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZMQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 52 00 65 00 61 00 64 00 28 00 24 00 } //1 .Read($
		$a_00_1 = {4e 00 65 00 74 00 2e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 54 00 43 00 50 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.Sockets.TCPClient
		$a_00_2 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00 28 00 } //1 .GetStream(
		$a_00_3 = {77 00 68 00 69 00 6c 00 65 00 } //1 while
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}