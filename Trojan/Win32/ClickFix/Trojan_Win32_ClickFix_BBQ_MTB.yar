
rule Trojan_Win32_ClickFix_BBQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 74 00 2e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 54 00 43 00 50 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.Sockets.TCPClient
		$a_00_1 = {2e 00 47 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00 28 00 24 00 } //1 .GetBytes($
		$a_00_2 = {2e 00 52 00 65 00 61 00 64 00 28 00 24 00 } //1 .Read($
		$a_00_3 = {2b 00 28 00 70 00 77 00 64 00 29 00 2e 00 50 00 61 00 74 00 68 00 } //1 +(pwd).Path
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}