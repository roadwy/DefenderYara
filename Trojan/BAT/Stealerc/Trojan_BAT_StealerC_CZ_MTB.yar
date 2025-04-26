
rule Trojan_BAT_StealerC_CZ_MTB{
	meta:
		description = "Trojan:BAT/StealerC.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 48 38 49 58 63 77 51 59 34 50 65 68 32 71 70 41 6e } //2 cH8IXcwQY4Peh2qpAn
		$a_81_1 = {78 72 55 74 42 56 6f 61 58 74 43 54 36 42 30 77 36 61 } //2 xrUtBVoaXtCT6B0w6a
		$a_81_2 = {76 4a 69 47 6c 30 31 55 55 4a 66 58 66 4e 57 61 73 33 } //2 vJiGl01UUJfXfNWas3
		$a_81_3 = {44 79 79 56 44 62 61 52 76 4d 31 59 66 49 71 39 69 6c } //1 DyyVDbaRvM1YfIq9il
		$a_81_4 = {4b 58 30 48 72 59 4e 65 62 } //1 KX0HrYNeb
		$a_81_5 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_6 = {43 4c 42 59 4e 41 4d 45 4f 58 59 41 4f 44 53 44 46 46 46 47 34 48 48 54 54 52 59 59 55 49 49 35 4f 4f 50 50 4c 4a } //1 CLBYNAMEOXYAODSDFFFG4HHTTRYYUII5OOPPLJ
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=10
 
}