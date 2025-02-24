
rule Ransom_MSIL_Majordom_YAA_MTB{
	meta:
		description = "Ransom:MSIL/Majordom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 00 75 00 70 00 73 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 73 00 20 00 42 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 42 00 79 00 20 00 4d 00 61 00 6a 00 6f 00 72 00 64 00 6f 00 6d 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 61 00 77 00 72 00 65 00 } //1 Oups Your Files Has Ben Encrypted By Majordom Ransomawre
		$a_01_1 = {6d 00 61 00 6a 00 6f 00 72 00 64 00 6f 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //11 majordom.Properties.Resources
		$a_01_2 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 46 00 69 00 6c 00 65 00 73 00 } //1 Delete Files
		$a_01_3 = {4d 61 6a 6f 72 64 6f 6d 20 56 34 2e 30 5c 63 6c 69 65 6e 74 5c 6d 61 6a 6f 72 64 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 6d 61 6a 6f 72 64 6f 6d 2e 70 64 62 } //1 Majordom V4.0\client\majordom\obj\Debug\majordom.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*11+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=14
 
}