
rule Trojan_Win32_Fragtor_RU_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 64 63 7a 63 63 78 7a 63 7a 78 63 78 78 63 78 63 78 7a 63 78 63 } //01 00  fdczccxzczxcxxcxcxzcxc
		$a_01_1 = {44 53 49 44 53 69 64 69 73 69 69 64 73 69 64 69 73 64 69 } //01 00  DSIDSidisiidsidisdi
		$a_01_2 = {33 34 7a 66 64 73 64 73 61 61 64 73 61 64 73 61 } //01 00  34zfdsdsaadsadsa
		$a_01_3 = {63 78 63 78 5a 7a 5a 7a 78 } //01 00  cxcxZzZzx
		$a_01_4 = {63 76 76 67 72 65 72 65 72 65 } //01 00  cvvgrerere
		$a_01_5 = {63 78 7a 63 78 7a 63 65 32 32 32 32 } //00 00  cxzcxzce2222
	condition:
		any of ($a_*)
 
}