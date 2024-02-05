
rule Trojan_MacOS_OpinionSpy_E_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 73 63 6f 72 65 2f 77 6f 72 6b 69 6e 67 63 6f 70 79 2f 4d 61 63 53 6e 69 66 66 65 72 2f } //01 00 
		$a_00_1 = {76 61 72 2f 74 6d 70 2f 4f 53 4d 49 4d 50 51 2e 73 6f 63 6b 65 74 } //01 00 
		$a_00_2 = {73 77 69 7a 7a 6c 65 73 61 66 61 72 69 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}