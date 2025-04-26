
rule Trojan_Win64_DllInject_GU_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f1 45 8a 14 10 } //1
		$a_01_1 = {44 30 14 0f } //1 い༔
		$a_01_2 = {48 ff c1 48 89 c8 48 81 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}