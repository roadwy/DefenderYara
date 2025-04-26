
rule Trojan_Win32_NetshAddFirewallRule_A_ibt{
	meta:
		description = "Trojan:Win32/NetshAddFirewallRule.A!ibt,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 [0-02] 73 00 62 00 66 00 77 00 72 00 75 00 6c 00 65 00 [0-0a] 64 00 69 00 72 00 3d 00 69 00 6e 00 [0-0a] 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}