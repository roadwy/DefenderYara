
rule Trojan_Win32_Lotok_GPA_MTB{
	meta:
		description = "Trojan:Win32/Lotok.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 b1 52 68 08 b5 09 00 c6 44 24 10 47 88 44 24 11 c6 44 24 12 54 c6 44 24 13 53 88 44 24 14 88 4c 24 15 c6 44 24 16 56 88 44 24 17 88 4c 24 18 c6 44 24 19 32 c6 44 24 1a 2e c6 44 24 1b 30 } //2
		$a_81_1 = {79 69 6e 67 67 73 68 69 73 68 69 7a } //2 yinggshishiz
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}