
rule Ransom_Win64_FileCoder_KU_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.KU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 00 68 00 65 00 6d 00 65 00 70 00 61 00 63 00 6b 00 } //1 themepack
		$a_00_1 = {62 00 6f 00 6f 00 74 00 73 00 65 00 63 00 74 00 2e 00 62 00 61 00 6b 00 } //1 bootsect.bak
		$a_00_2 = {74 00 6f 00 72 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //1 tor browser
		$a_01_3 = {21 20 45 4e 43 52 59 50 54 49 4e 47 } //1 ! ENCRYPTING
		$a_01_4 = {44 6f 6e 74 53 75 69 63 69 64 65 21 31 34 38 38 } //1 DontSuicide!1488
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}