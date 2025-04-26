
rule Trojan_Win32_NetShFirewallRuleAdd_A{
	meta:
		description = "Trojan:Win32/NetShFirewallRuleAdd.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6e 00 65 00 74 00 73 00 68 00 [0-10] 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 [0-05] 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 [0-05] 61 00 64 00 64 00 [0-05] 72 00 75 00 6c 00 65 00 [0-05] 6e 00 61 00 6d 00 65 00 3d 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}