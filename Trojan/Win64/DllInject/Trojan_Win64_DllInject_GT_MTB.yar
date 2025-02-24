
rule Trojan_Win64_DllInject_GT_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f6 } //1
		$a_02_1 = {45 8a 1c 14 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 [0-04] 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}