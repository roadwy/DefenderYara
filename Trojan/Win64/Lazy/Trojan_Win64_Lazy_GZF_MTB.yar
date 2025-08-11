
rule Trojan_Win64_Lazy_GZF_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 74 24 21 36 80 74 24 22 37 80 74 24 23 38 80 74 24 24 39 80 74 24 25 3a 80 74 24 26 3b 80 74 24 27 3c 66 89 4c 24 28 80 f1 3d 80 74 24 29 3e 34 3f c6 44 24 20 31 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}