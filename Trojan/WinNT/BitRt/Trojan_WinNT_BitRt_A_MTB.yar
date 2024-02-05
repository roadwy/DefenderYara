
rule Trojan_WinNT_BitRt_A_MTB{
	meta:
		description = "Trojan:WinNT/BitRt.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //01 00 
		$a_02_1 = {62 69 74 73 61 64 6d 69 6e 2e 65 78 65 20 2f 74 72 61 6e 73 66 65 72 90 02 10 75 72 6c 90 02 20 73 74 72 90 02 05 66 69 6c 65 6e 61 6d 65 90 00 } //02 00 
		$a_00_2 = {3a 2f 2f 67 72 6e 74 65 78 70 72 65 73 73 63 6f 75 72 69 65 72 2e 63 6f 6d 2f 46 69 6c 65 2f } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}