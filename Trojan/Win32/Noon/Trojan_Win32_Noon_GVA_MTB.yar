
rule Trojan_Win32_Noon_GVA_MTB{
	meta:
		description = "Trojan:Win32/Noon.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 d1 44 20 c1 08 d0 30 c8 44 08 c2 30 c2 74 20 } //3
		$a_01_1 = {0f 94 c2 08 d1 44 30 c2 44 30 c1 80 f1 01 08 d1 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}