
rule Ransom_AndroidOS_Small_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Small.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {54 6f 20 63 6f 6e 74 69 6e 75 65 2c 20 79 6f 75 20 6d 75 73 74 20 61 63 74 69 76 61 74 65 20 74 68 65 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e 20 43 6c 69 63 6b 20 74 6f 20 61 63 74 69 76 61 74 65 } //1 To continue, you must activate the application. Click to activate
		$a_00_1 = {66 6f 72 63 65 2d 6c 6f 63 6b 65 64 } //1 force-locked
		$a_00_2 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 74 65 73 74 6c 6f 63 6b } //1 com.example.testlock
		$a_00_3 = {4d 61 79 20 6c 6f 73 65 20 75 73 65 72 20 64 61 74 61 2e 20 44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 } //1 May lose user data. Do you want to continue
		$a_00_4 = {77 61 73 53 63 72 65 65 6e 4f 6e } //1 wasScreenOn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}