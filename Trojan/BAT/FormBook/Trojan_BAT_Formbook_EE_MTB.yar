
rule Trojan_BAT_Formbook_EE_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 36 38 61 38 62 38 66 33 2d 34 65 31 31 2d 34 62 33 65 2d 61 31 39 65 2d 66 31 64 33 64 34 65 64 38 31 36 31 } //1 $68a8b8f3-4e11-4b3e-a19e-f1d3d4ed8161
		$a_81_1 = {32 36 66 63 32 2e 72 65 73 6f 75 72 63 65 73 } //1 26fc2.resources
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {66 72 6f 7a 65 6e } //1 frozen
		$a_81_5 = {31 2e 65 78 65 } //1 1.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}