
rule Trojan_Win32_Neoreblamy_GPF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 05 6a 07 59 cd 29 6a 01 68 15 00 00 40 6a 03 e8 cc 3b 00 00 83 c4 0c 6a 03 e8 d1 2b } //3
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 00 72 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}