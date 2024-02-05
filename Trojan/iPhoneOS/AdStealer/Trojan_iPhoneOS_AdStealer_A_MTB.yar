
rule Trojan_iPhoneOS_AdStealer_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/AdStealer.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 62 69 74 73 69 6d 70 6c 65 2e 53 69 6d 70 6c 79 42 54 43 } //01 00 
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 63 6f 6d 2e 4d 61 6b 65 41 4c 69 66 65 2e 76 65 72 69 66 79 64 70 2e 70 6c 69 73 74 } //01 00 
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 55 46 43 50 72 6f 2e 61 70 70 2f 55 46 43 50 72 6f } //01 00 
		$a_00_3 = {63 6f 6d 2e 6d 65 6f 79 65 75 2e 66 64 2e 70 6c 69 73 74 } //01 00 
		$a_00_4 = {69 64 66 63 70 2e 64 79 6c 69 62 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}