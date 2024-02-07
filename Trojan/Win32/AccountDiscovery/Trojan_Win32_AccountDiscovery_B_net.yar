
rule Trojan_Win32_AccountDiscovery_B_net{
	meta:
		description = "Trojan:Win32/AccountDiscovery.B!net,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //01 00  net accounts
		$a_00_1 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //01 00  net.exe accounts
		$a_00_2 = {6e 00 65 00 74 00 31 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //01 00  net1 accounts
		$a_00_3 = {6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //00 00  net1.exe accounts
	condition:
		any of ($a_*)
 
}