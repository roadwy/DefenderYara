
rule Trojan_Win64_Lazy_GBN_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 f7 df 41 32 f3 41 80 ea 9f 4e 8d 5c 1c 30 4d 8b 54 43 f8 } //5
		$a_01_1 = {48 b8 d3 6d 18 e2 b2 55 66 d6 48 89 44 24 40 48 89 4c 24 48 66 0f 6f 44 24 40 66 0f ef 44 24 60 66 0f 7f 44 24 40 48 8d 44 24 40 4c 8b c3 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00 75 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}