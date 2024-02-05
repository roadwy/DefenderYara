
rule Trojan_BAT_Zusy_PSWN_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSWN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {51 6a 41 49 67 77 53 65 } //02 00 
		$a_01_1 = {7a 6b 76 56 68 73 46 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00 
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}