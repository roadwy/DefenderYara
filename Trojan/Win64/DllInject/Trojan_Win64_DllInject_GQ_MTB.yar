
rule Trojan_Win64_DllInject_GQ_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 c8 48 8b c6 41 ff c0 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 49 0f af ce 8a 44 0d 87 43 32 04 0a 41 88 01 49 ff c1 45 3b c5 72 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}