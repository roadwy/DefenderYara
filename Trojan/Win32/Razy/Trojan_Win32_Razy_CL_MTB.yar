
rule Trojan_Win32_Razy_CL_MTB{
	meta:
		description = "Trojan:Win32/Razy.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 d7 21 fa 31 08 40 39 f0 75 eb } //2
		$a_03_1 = {31 1f 81 c7 04 00 00 00 81 c2 90 02 04 29 f1 39 c7 75 e7 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}