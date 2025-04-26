
rule Trojan_Win32_Neoreblamy_GPO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {64 77 62 71 63 5a 74 5a 4d 78 58 49 4d } //3 dwbqcZtZMxXIM
		$a_81_1 = {63 4e 51 50 61 55 42 42 6f 65 4f 79 58 4c 4a 49 47 74 4e 45 50 58 6e } //2 cNQPaUBBoeOyXLJIGtNEPXn
		$a_81_2 = {6b 6b 51 72 4c 78 6f 66 70 4b 43 70 67 63 62 73 7a 65 65 59 77 4f 68 77 41 } //1 kkQrLxofpKCpgcbszeeYwOhwA
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}