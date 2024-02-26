
rule Trojan_Win64_Lazy_GMP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 68 48 b8 4d f0 90 8a 5b 81 b8 04 48 89 44 24 40 48 89 4c 24 48 66 0f 6f 44 24 40 66 0f ef 44 24 60 66 0f 7f 44 24 40 48 8d 44 24 40 4c 8b c3 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}