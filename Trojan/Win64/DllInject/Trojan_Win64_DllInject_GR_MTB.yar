
rule Trojan_Win64_DllInject_GR_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 44 0d 87 43 32 04 ?? 41 88 ?? 49 ff ?? 45 3b ?? 72 } //1
		$a_02_1 = {48 f7 e1 48 c1 ea ?? 48 } //1
		$a_01_2 = {48 2b c8 49 0f af ce } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}