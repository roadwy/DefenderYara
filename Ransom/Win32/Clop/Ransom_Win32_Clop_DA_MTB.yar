
rule Ransom_Win32_Clop_DA_MTB{
	meta:
		description = "Ransom:Win32/Clop.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 4c 30 50 52 45 41 44 4d 45 2e 74 78 74 } //1 CL0PREADME.txt
		$a_81_1 = {2e 43 6c 30 70 } //1 .Cl0p
		$a_81_2 = {72 65 73 33 2e 74 78 74 2e 43 49 6f 70 } //1 res3.txt.CIop
		$a_81_3 = {52 45 41 44 4d 45 5f 52 45 41 44 4d 45 2e 74 78 74 } //1 README_README.txt
		$a_81_4 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=3
 
}