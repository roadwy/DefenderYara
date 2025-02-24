
rule Trojan_Win32_Banker_EM_MTB{
	meta:
		description = "Trojan:Win32/Banker.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 c6 45 ee e9 8a 45 f4 88 45 ef 8b 45 f4 c1 e8 08 88 45 f0 8b 45 f4 c1 e8 10 88 45 f1 8b 45 f4 c1 e8 18 88 45 f2 c6 45 f3 c3 } //3
		$a_01_1 = {66 69 6c 69 61 74 69 6f 6e } //1 filiation
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}