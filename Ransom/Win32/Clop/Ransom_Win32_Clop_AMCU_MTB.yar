
rule Ransom_Win32_Clop_AMCU_MTB{
	meta:
		description = "Ransom:Win32/Clop.AMCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {2e 00 43 00 5f 00 2d 00 5f 00 4c 00 5f 00 2d 00 5f 00 30 00 5f 00 2d 00 5f 00 50 00 } //.  5
		$a_80_1 = {57 69 6e 53 79 70 54 65 73 74 43 68 61 6e 67 65 } //WinSypTestChange  3
		$a_80_2 = {44 45 4b 4a 55 42 46 53 54 58 52 59 59 48 48 4a } //DEKJUBFSTXRYYHHJ  1
		$a_80_3 = {41 41 41 5f 52 45 41 44 5f 41 41 41 2e 54 58 54 } //AAA_READ_AAA.TXT  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}