
rule Trojan_BAT_FormBook_MBBK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 00 32 00 44 00 35 00 48 00 37 00 52 00 35 00 45 00 52 00 34 00 37 00 35 00 38 00 38 00 38 00 35 00 37 00 47 00 37 00 35 00 34 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_3 = {53 79 73 74 65 6d 2e 41 63 74 69 76 61 74 6f 72 } //01 00 
		$a_01_4 = {49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}