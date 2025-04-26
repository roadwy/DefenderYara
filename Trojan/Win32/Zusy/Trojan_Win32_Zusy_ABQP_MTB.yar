
rule Trojan_Win32_Zusy_ABQP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ABQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 73 6a 69 6f 67 73 6a 67 69 6f 41 4a 49 6a 73 72 67 68 } //2 BsjiogsjgioAJIjsrgh
		$a_01_1 = {4b 6a 73 6a 6f 69 67 68 73 6a 72 68 67 69 73 72 6a } //2 Kjsjoighsjrhgisrj
		$a_01_2 = {50 6a 69 6f 73 67 6a 69 75 6f 73 6a 67 68 6f 73 65 6a 67 68 69 } //2 Pjiosgjiuosjghosejghi
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}