
rule Trojan_Linux_RemovalOnHost_F{
	meta:
		description = "Trojan:Linux/RemovalOnHost.F,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 00 6d 00 20 00 2d 00 72 00 66 00 } //01 00 
		$a_00_1 = {72 00 6d 00 20 00 2d 00 66 00 72 00 } //01 00 
		$a_00_2 = {72 00 6d 00 20 00 2d 00 72 00 20 00 2d 00 66 00 } //01 00 
		$a_00_3 = {72 00 6d 00 20 00 2d 00 66 00 20 00 2d 00 72 00 } //05 00 
		$a_00_4 = {20 00 2f 00 20 00 } //0a 00 
		$a_00_5 = {2d 00 2d 00 6e 00 6f 00 2d 00 70 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 2d 00 72 00 6f 00 6f 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}