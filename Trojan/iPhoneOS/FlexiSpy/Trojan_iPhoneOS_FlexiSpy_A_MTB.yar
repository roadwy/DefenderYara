
rule Trojan_iPhoneOS_FlexiSpy_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/FlexiSpy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 2e 6c 73 61 6c 63 6f 72 65 2f 73 68 61 72 65 73 2f } //01 00 
		$a_00_1 = {25 40 2f 65 74 63 2f 46 6f 72 63 65 4f 75 74 2e 70 6c 69 73 74 } //01 00 
		$a_00_2 = {4d 53 46 53 50 55 74 69 6c 73 } //01 00 
		$a_00_3 = {63 61 70 74 75 72 65 53 74 61 72 74 65 64 3a } //00 00 
		$a_00_4 = {5d 04 00 } //00 5d 
	condition:
		any of ($a_*)
 
}