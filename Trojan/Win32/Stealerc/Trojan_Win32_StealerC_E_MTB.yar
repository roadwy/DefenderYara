
rule Trojan_Win32_StealerC_E_MTB{
	meta:
		description = "Trojan:Win32/StealerC.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {72 61 78 75 78 6f 66 6f 68 69 66 61 6b 61 74 61 73 6f 6e 61 62 65 6b 75 76 6f } //1 raxuxofohifakatasonabekuvo
		$a_81_1 = {66 61 68 75 62 61 72 6f 63 75 76 75 76 65 6a 65 67 6f 76 69 6d 69 73 69 77 75 } //1 fahubarocuvuvejegovimisiwu
		$a_81_2 = {6c 6f 79 75 73 6f 74 6f 6e 6f 66 61 73 75 62 61 } //1 loyusotonofasuba
		$a_81_3 = {6a 6f 6b 65 64 69 74 65 72 6f 76 69 77 65 64 61 72 61 66 69 6e 61 79 6f 67 } //1 jokediteroviwedarafinayog
		$a_81_4 = {6a 6f 77 75 68 61 72 61 74 61 70 69 79 69 6c 69 6a 61 64 65 7a 75 6d 61 64 61 79 65 64 75 6a 65 } //1 jowuharatapiyilijadezumadayeduje
		$a_81_5 = {6c 75 6d 65 6a 61 73 75 72 69 6e 69 73 6f 6d 65 6b 65 70 } //1 lumejasurinisomekep
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}