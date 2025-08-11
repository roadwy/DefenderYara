
rule Trojan_Win64_Lazy_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 5f 41 5e 41 5d 41 5c 5f 5e 5d c3 30 40 02 00 91 40 02 00 91 40 02 00 45 40 02 00 45 40 02 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Lazy_GZZ_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 74 24 21 39 80 74 24 22 3a 80 74 24 23 3b 80 74 24 24 3c 80 74 24 25 3d 80 74 24 26 3e 80 74 24 27 3f 66 89 4c 24 28 80 f1 40 80 74 24 29 41 34 42 c6 44 24 20 58 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}