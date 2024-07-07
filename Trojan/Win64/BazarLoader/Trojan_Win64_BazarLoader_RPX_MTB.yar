
rule Trojan_Win64_BazarLoader_RPX_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8b 04 87 43 89 04 8b 41 8d 40 01 41 ff c1 45 33 c0 3b c3 44 0f 45 c0 45 3b ca 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_BazarLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c2 7f 89 d7 c1 ef 1f c1 fa 06 01 fa 89 d7 c1 e7 07 29 fa 01 f2 83 c2 7f 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_BazarLoader_RPX_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 0c 01 41 32 0c 3e 88 0c 38 89 f9 83 e1 1f 42 0f b6 14 01 41 32 14 3e 88 14 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}