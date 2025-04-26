
rule Trojan_Win32_Razy_CU_MTB{
	meta:
		description = "Trojan:Win32/Razy.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 57 5f 81 c1 [0-04] 81 fb 09 72 00 01 75 a3 } //2
		$a_01_1 = {31 32 01 c0 42 89 c9 39 fa 75 dc } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}