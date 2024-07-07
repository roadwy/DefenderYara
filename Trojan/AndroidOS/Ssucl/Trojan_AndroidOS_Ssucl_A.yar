
rule Trojan_AndroidOS_Ssucl_A{
	meta:
		description = "Trojan:AndroidOS/Ssucl.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6c 61 63 6f 2e 6b 69 63 6b 73 2d 61 73 73 2e 6e 65 74 00 } //1
		$a_01_1 = {61 70 70 5f 64 61 74 61 2f 73 76 63 68 6f 73 74 73 2e 65 78 65 00 } //1
		$a_01_2 = {68 61 6e 64 6c 65 5f 75 70 6c 6f 61 64 2e 70 68 70 00 } //1
		$a_01_3 = {74 69 6c 61 62 2e 6d 73 6e 2e 53 4d 53 5f 53 45 4e 54 00 } //1
		$a_01_4 = {7c 4e 45 57 5f 48 45 4c 4c 4f 57 7c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}