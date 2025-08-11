
rule Trojan_Win64_Lazy_DA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 07 49 8b c6 48 f7 e1 48 c1 ea 03 48 6b c2 0f 48 2b c8 0f b6 44 0c 20 43 32 04 0a 43 88 04 02 41 ff c3 49 ff c2 49 63 cb 48 3b 4b 10 } //1
		$a_01_1 = {48 8b 0f 49 8b c6 49 f7 e1 48 c1 ea 02 48 8d 04 52 48 03 c0 4c 2b c8 42 0f b6 44 0d b7 43 32 04 02 41 88 04 0a 41 ff c3 49 ff c2 4d 63 cb 4c 3b 4b 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}