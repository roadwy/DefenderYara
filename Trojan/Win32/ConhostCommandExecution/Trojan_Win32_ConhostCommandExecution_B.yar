
rule Trojan_Win32_ConhostCommandExecution_B{
	meta:
		description = "Trojan:Win32/ConhostCommandExecution.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 02 00 00 03 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //f6 ff 
		$a_02_1 = {66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 90 02 10 46 00 6f 00 72 00 63 00 65 00 56 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}