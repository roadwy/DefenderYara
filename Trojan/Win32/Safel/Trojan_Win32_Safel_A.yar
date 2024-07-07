
rule Trojan_Win32_Safel_A{
	meta:
		description = "Trojan:Win32/Safel.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 8d bd c1 3f } //2
		$a_01_1 = {9f a9 a2 af a9 a1 f1 ea af a4 e3 00 } //2
		$a_09_2 = {22 25 73 22 00 } //1
		$a_09_3 = {73 66 6c 73 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_09_2  & 1)*1+(#a_09_3  & 1)*1) >=4
 
}