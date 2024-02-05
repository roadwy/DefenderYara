
rule Trojan_MacOS_CrescentCore_A_MTB{
	meta:
		description = "Trojan:MacOS/CrescentCore.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6c 2e 72 2e 6c 2e 6d } //01 00 
		$a_01_1 = {2f 44 65 73 6b 74 6f 70 2f 57 61 6e 69 6e 67 43 72 65 73 63 65 6e 74 2f 57 61 6e 69 6e 67 43 72 65 73 63 65 6e 74 2f } //01 00 
		$a_00_2 = {69 6f 72 65 67 20 2d 6c 20 7c 20 67 72 65 70 20 2d 65 20 4d 61 6e 75 66 61 63 74 75 72 65 72 } //01 00 
		$a_00_3 = {72 6d 20 2d 72 66 20 2f 74 6d 70 2f 55 70 64 61 74 65 72 2e 7a 69 70 } //01 00 
		$a_00_4 = {44 6f 77 6e 6c 6f 61 64 4f 66 66 65 72 4f 62 6a 65 63 74 } //00 00 
		$a_00_5 = {5d 04 00 00 d8 01 04 80 5c 28 } //00 00 
	condition:
		any of ($a_*)
 
}