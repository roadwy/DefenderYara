
rule Trojan_BAT_BitRAT_NAT_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 90 01 02 00 0a 00 73 90 01 02 00 0a 72 90 01 02 00 70 28 90 01 02 00 0a 0a 2b 00 06 90 00 } //01 00 
		$a_01_1 = {4c 6f 61 6d 6e 62 6f 61 2e 4d 61 69 6e 57 69 6e 64 6f 77 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Loamnboa.MainWindow.resources
		$a_01_2 = {48 69 65 7a } //00 00  Hiez
	condition:
		any of ($a_*)
 
}