
rule Trojan_WinNT_DldrAgent_A_MTB{
	meta:
		description = "Trojan:WinNT/DldrAgent.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {73 65 63 75 72 65 2d 64 6e 73 2d 72 65 73 6f 6c 76 65 2e 63 6f 6d 2f 90 02 10 2e 70 6e 67 90 00 } //02 00 
		$a_02_1 = {66 61 63 74 75 72 61 63 69 6f 6e 6d 78 2e 6e 65 74 2f 90 02 10 2e 70 6e 67 90 00 } //01 00 
		$a_00_2 = {4d 69 63 72 6f 73 6f 66 74 5f 53 65 63 75 72 65 5f 44 6f 63 75 6d 65 6e 74 5f 56 69 65 77 65 72 } //01 00 
		$a_00_3 = {53 65 63 75 72 65 5f 56 69 65 77 65 72 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}