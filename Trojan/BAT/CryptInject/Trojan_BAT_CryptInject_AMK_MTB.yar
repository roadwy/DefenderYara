
rule Trojan_BAT_CryptInject_AMK_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 02 00 00 00 2c 00 00 00 15 00 00 00 56 00 00 00 6a 00 00 00 3b 00 00 00 0e 00 00 00 01 00 00 00 02 } //5
		$a_80_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //get_CurrentDomain  3
		$a_80_2 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //add_AssemblyResolve  3
		$a_80_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //ToBase64String  3
		$a_80_4 = {4f 49 41 44 4e 41 49 53 33 71 } //OIADNAIS3q  3
		$a_80_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //GetExecutingAssembly  3
	condition:
		((#a_00_0  & 1)*5+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=20
 
}