
rule Trojan_Win64_DllInject_GVA_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 10 } //3
		$a_01_1 = {44 30 14 0f } //2 い༔
		$a_01_2 = {48 89 c8 48 81 f9 d3 21 1c 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}