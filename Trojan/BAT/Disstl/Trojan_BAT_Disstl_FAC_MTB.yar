
rule Trojan_BAT_Disstl_FAC_MTB{
	meta:
		description = "Trojan:BAT/Disstl.FAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1a 00 07 00 00 "
		
	strings :
		$a_80_0 = {68 6a 69 77 65 79 6b 61 6b 73 64 } //hjiweykaksd  5
		$a_80_1 = {50 61 73 73 77 6f 72 64 44 65 72 69 76 65 42 79 74 65 73 } //PasswordDeriveBytes  5
		$a_80_2 = {44 69 73 63 6f 72 64 } //Discord  5
		$a_80_3 = {61 76 61 74 61 72 5f 75 72 6c } //avatar_url  4
		$a_80_4 = {44 61 74 61 5c 6c 69 62 6c 61 6e 67 2e 64 6c 6c } //Data\liblang.dll  4
		$a_80_5 = {4c 4f 47 2e 44 4c 4c } //LOG.DLL  4
		$a_80_6 = {42 46 57 41 } //BFWA  4
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4) >=26
 
}