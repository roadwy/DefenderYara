
rule Trojan_MacOS_HackBrow_A_MTB{
	meta:
		description = "Trojan:MacOS/HackBrow.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 2d 62 72 6f 77 73 65 72 2d 64 61 74 61 2f } //01 00 
		$a_01_1 = {2f 62 72 6f 77 69 6e 67 64 61 74 61 2f 63 72 65 64 69 74 63 61 72 64 2f 63 72 65 64 69 74 63 61 72 64 } //01 00 
		$a_01_2 = {70 72 6f 76 69 64 65 72 2e 50 69 63 6b 42 72 6f 77 73 65 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}