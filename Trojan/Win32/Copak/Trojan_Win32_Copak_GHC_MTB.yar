
rule Trojan_Win32_Copak_GHC_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 16 81 c6 90 01 04 01 c9 39 de 75 ed 90 00 } //10
		$a_03_1 = {31 19 81 ef 90 01 04 81 c1 90 01 04 4e 81 c6 90 01 04 39 c1 75 e2 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}