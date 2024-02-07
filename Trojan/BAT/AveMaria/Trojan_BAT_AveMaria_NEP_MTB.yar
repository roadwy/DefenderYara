
rule Trojan_BAT_AveMaria_NEP_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 61 63 69 66 73 64 74 72 73 64 64 68 68 6a 67 73 67 64 73 64 64 73 64 68 73 64 68 73 64 6c 55 70 64 61 74 65 } //02 00  FacifsdtrsddhhjgsgdsddsdhsdhsdlUpdate
		$a_01_1 = {46 61 69 6c 64 67 66 73 64 74 72 74 72 64 68 61 73 64 63 64 67 66 65 73 64 64 67 68 64 73 68 73 64 68 42 65 67 69 6e } //02 00  FaildgfsdtrtrdhasdcdgfesddghdshsdhBegin
		$a_01_2 = {53 75 63 7a 64 76 73 64 73 64 76 66 63 74 67 6a 65 73 67 64 64 73 64 72 64 73 61 73 64 63 65 73 73 } //02 00  Suczdvsdsdvfctgjesgddsdrdsasdcess
		$a_01_3 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //01 00  ObfuscatedByGoliath
		$a_01_4 = {43 00 3a 00 5c 00 73 00 6f 00 67 00 67 00 67 00 67 00 67 00 67 00 67 00 67 00 67 00 6d 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 } //01 00  C:\sogggggggggmedirectory
		$a_01_5 = {43 00 3a 00 5c 00 4e 00 65 00 64 00 64 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 77 00 54 00 65 00 6d 00 70 00 } //00 00  C:\NeddssssssssssssssddddddddddddddddddddwTemp
	condition:
		any of ($a_*)
 
}