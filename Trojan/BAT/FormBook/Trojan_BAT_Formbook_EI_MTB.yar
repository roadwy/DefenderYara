
rule Trojan_BAT_Formbook_EI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 61 63 30 34 35 65 32 35 2d 35 64 39 65 2d 34 32 62 38 2d 61 31 63 65 2d 34 63 33 61 39 35 39 36 30 65 61 65 } //10 $ac045e25-5d9e-42b8-a1ce-4c3a95960eae
		$a_81_1 = {73 74 75 62 5f 32 2e 6e 65 74 72 73 72 63 2e 72 65 73 6f 75 72 63 65 73 } //1 stub_2.netrsrc.resources
		$a_81_2 = {50 45 4c 6f 63 6b 20 53 6f 66 74 77 61 72 65 } //1 PELock Software
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {2e 6e 65 74 73 68 72 69 6e 6b 20 73 74 75 62 } //1 .netshrink stub
		$a_81_6 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //1 ClassLibrary1
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}