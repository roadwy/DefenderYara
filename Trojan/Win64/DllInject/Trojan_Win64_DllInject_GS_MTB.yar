
rule Trojan_Win64_DllInject_GS_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f1 } //1
		$a_01_1 = {45 8a 14 10 } //1
		$a_02_2 = {44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 [0-04] 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}