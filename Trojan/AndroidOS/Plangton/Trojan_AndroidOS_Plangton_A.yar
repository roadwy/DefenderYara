
rule Trojan_AndroidOS_Plangton_A{
	meta:
		description = "Trojan:AndroidOS/Plangton.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 6d 6d 61 6e 64 73 74 61 74 75 73 } //01 00 
		$a_01_1 = {63 6f 6d 2e 61 70 70 65 72 68 61 6e 64 2e 67 6c 6f 62 61 6c } //01 00 
		$a_01_2 = {4d 5f 53 45 52 56 45 52 5f 55 52 4c } //01 00 
		$a_01_3 = {77 61 73 20 61 63 74 69 76 61 74 65 64 2c 20 53 41 42 41 42 41 21 21 21 } //00 00 
	condition:
		any of ($a_*)
 
}