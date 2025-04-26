
rule Trojan_Win64_DllInject_GA_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 c9 48 b8 8f e3 38 8e e3 38 8e e3 41 ff c1 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 49 0f af cb 8a 44 0c 20 42 32 04 17 41 88 02 49 ff c2 44 3b cb 72 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}