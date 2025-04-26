
rule Trojan_Win64_DllInject_GC_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 83 c2 06 48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 0f b6 44 0c 20 43 32 44 0d fa 41 88 41 ff 49 ff c8 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}