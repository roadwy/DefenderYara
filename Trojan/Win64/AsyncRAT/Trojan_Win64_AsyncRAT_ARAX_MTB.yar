
rule Trojan_Win64_AsyncRAT_ARAX_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 42 32 04 09 88 04 29 80 c2 05 41 ff c0 4c 8b 0f 41 8b c8 48 8b 47 08 49 2b c1 48 3b c8 72 de } //2
		$a_01_1 = {0f b6 c2 42 32 04 09 88 04 29 80 c2 05 41 ff c0 4c 8b 0f 48 8b 47 08 49 2b c1 41 8b c8 48 3b c8 72 de } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}