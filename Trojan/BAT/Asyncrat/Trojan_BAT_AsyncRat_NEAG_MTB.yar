
rule Trojan_BAT_AsyncRat_NEAG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 03 00 00 0a 0a 06 72 01 00 00 70 6f 04 00 00 0a 06 72 17 00 00 70 6f 05 00 00 0a 06 17 6f 06 00 00 0a 06 17 6f 07 00 00 0a 06 28 08 00 00 0a 26 2a } //02 00 
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //02 00 
		$a_01_2 = {45 00 6e 00 63 00 6f 00 64 00 65 00 64 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}