
rule Trojan_Win64_Lazy_GMN_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 08 66 89 5c 24 68 48 89 5c 24 6e 48 89 5c 24 76 33 c0 66 89 44 24 6b 88 44 24 6d 66 89 44 24 6e 88 44 24 70 66 89 44 24 71 88 44 24 73 66 89 44 24 74 88 44 24 76 66 89 44 24 77 88 44 24 79 66 89 44 24 7a 88 44 24 7c 89 5c 24 34 89 5c 24 64 0f 28 44 24 20 66 0f 7f 44 24 20 4c 8d 85 b0 01 00 00 48 8d 54 24 20 48 8d 4c 24 30 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}