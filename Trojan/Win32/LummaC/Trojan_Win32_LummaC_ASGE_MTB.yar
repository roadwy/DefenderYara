
rule Trojan_Win32_LummaC_ASGE_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c2 8b 55 f4 33 d0 89 55 f4 e8 } //2
		$a_01_1 = {81 01 e1 34 ef c6 c3 29 11 c3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}