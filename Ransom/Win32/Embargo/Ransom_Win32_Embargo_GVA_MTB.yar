
rule Ransom_Win32_Embargo_GVA_MTB{
	meta:
		description = "Ransom:Win32/Embargo.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 6d 62 61 72 67 6f 3a 3a } //1 embargo::
		$a_01_1 = {6c 6f 67 66 69 6c 65 65 6d 62 61 72 67 6f } //3 logfileembargo
		$a_81_2 = {46 61 69 6c 65 64 20 73 65 6c 66 64 65 6c 65 74 65 3a } //1 Failed selfdelete:
		$a_81_3 = {44 65 6c 65 74 65 64 20 20 73 68 61 64 6f 77 73 } //1 Deleted  shadows
		$a_01_4 = {65 6d 62 61 72 67 6f 3a 3a 77 69 6e 6c 69 62 3a 3a 65 6e 63 72 79 70 74 } //2 embargo::winlib::encrypt
		$a_81_5 = {46 61 69 6c 65 64 20 74 6f 20 72 65 6d 6f 76 65 20 73 68 61 64 6f 77 3a } //1 Failed to remove shadow:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*2+(#a_81_5  & 1)*1) >=9
 
}