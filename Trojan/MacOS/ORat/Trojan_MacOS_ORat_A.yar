
rule Trojan_MacOS_ORat_A{
	meta:
		description = "Trojan:MacOS/ORat.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 72 61 74 2f 75 74 69 6c 73 } //01 00 
		$a_00_1 = {6f 72 61 74 2f 65 6e 64 70 6f 69 6e 74 } //01 00 
		$a_00_2 = {6f 72 61 74 2f 63 6d 64 2f 61 67 65 6e 74 2f 61 70 70 2f 73 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}