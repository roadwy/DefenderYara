
rule Trojan_Win32_ClickFix_AJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,33 00 33 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {6e 00 65 00 74 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 74 00 63 00 70 00 63 00 6c 00 69 00 65 00 6e 00 74 00 28 00 } //10 net.sockets.tcpclient(
		$a_00_2 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //10 net.webclient
		$a_00_3 = {3b 00 77 00 68 00 69 00 6c 00 65 00 28 00 24 00 } //10 ;while($
		$a_00_4 = {29 00 2e 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 } //10 ).connected
		$a_00_5 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 } //1 .downloadfile(
		$a_00_6 = {2e 00 70 00 73 00 31 00 3b 00 20 00 65 00 78 00 69 00 74 00 } //1 .ps1; exit
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=51
 
}