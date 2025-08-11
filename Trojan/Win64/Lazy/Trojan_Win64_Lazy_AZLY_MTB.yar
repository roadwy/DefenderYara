
rule Trojan_Win64_Lazy_AZLY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AZLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 44 24 6b 88 44 24 6d 66 89 44 24 6e 88 44 24 70 66 89 44 24 71 88 44 24 73 66 89 44 24 74 88 44 24 76 66 89 44 24 77 88 44 24 79 66 89 44 24 7a 88 44 24 7c 89 7c 24 64 0f 10 03 0f 29 45 d0 89 7c 24 34 c6 44 24 68 01 48 8d 55 50 48 8d 4c 24 20 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}