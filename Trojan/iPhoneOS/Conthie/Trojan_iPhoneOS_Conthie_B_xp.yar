
rule Trojan_iPhoneOS_Conthie_B_xp{
	meta:
		description = "Trojan:iPhoneOS/Conthie.B!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 74 65 6d 70 74 73 54 6f 52 65 63 72 65 61 74 65 55 70 6c 6f 61 64 54 61 73 6b 73 46 6f 72 42 61 63 6b 67 72 6f 75 6e 64 53 65 73 73 69 6f 6e 73 } //01 00 
		$a_00_1 = {73 74 61 72 74 4d 6f 6e 69 74 6f 72 69 6e 67 } //01 00 
		$a_00_2 = {69 6e 6b 2e 75 73 68 6f 77 2e 61 70 70 2e 63 6f 6d 2e 61 70 70 73 2e 61 67 65 6e 74 33 38 31 } //01 00 
		$a_00_3 = {31 30 37 2e 31 35 31 2e 31 39 34 2e 31 31 36 3a 38 30 38 30 } //00 00 
	condition:
		any of ($a_*)
 
}