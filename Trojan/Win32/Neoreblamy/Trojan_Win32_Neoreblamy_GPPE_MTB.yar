
rule Trojan_Win32_Neoreblamy_GPPE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {6a 79 46 47 64 58 67 69 4e 49 74 6a 6c 47 62 73 6e 47 55 47 77 6d 41 } //3 jyFGdXgiNItjlGbsnGUGwmA
		$a_81_1 = {72 6a 62 6b 59 50 69 43 43 65 4b 46 52 78 63 48 51 59 50 68 } //2 rjbkYPiCCeKFRxcHQYPh
		$a_81_2 = {68 64 78 59 4f 4e 65 72 56 5a 4a 66 64 62 77 59 4f 58 4b 61 } //1 hdxYONerVZJfdbwYOXKa
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}