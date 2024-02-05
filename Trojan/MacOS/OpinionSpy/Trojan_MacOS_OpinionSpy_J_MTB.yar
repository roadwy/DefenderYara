
rule Trojan_MacOS_OpinionSpy_J_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //01 00 
		$a_01_1 = {50 72 65 6d 69 65 72 4f 70 69 6e 69 6f 6e 20 69 73 20 61 20 43 6f 6d 73 63 6f 72 65 20 62 72 61 6e 64 2c 20 70 72 6f 76 69 64 65 64 20 62 79 20 56 6f 69 63 65 46 69 76 65 20 49 6e 63 2e 2c 20 61 20 43 6f 6d 73 63 6f 72 65 20 63 6f 6d 70 61 6e 79 2e } //01 00 
		$a_00_2 = {70 6f 44 65 6d 6f 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}