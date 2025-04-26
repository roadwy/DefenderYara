
rule Trojan_Win64_BazarLoader_RPY_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 00 68 00 72 00 6f 00 75 00 67 00 68 00 53 00 6c 00 6f 00 77 00 6c 00 79 00 } //1 ThroughSlowly
		$a_01_1 = {52 00 65 00 67 00 75 00 6c 00 61 00 72 00 6c 00 79 00 50 00 6c 00 61 00 79 00 } //1 RegularlyPlay
		$a_01_2 = {46 00 61 00 73 00 74 00 42 00 79 00 } //1 FastBy
		$a_01_3 = {44 00 69 00 66 00 66 00 65 00 72 00 65 00 6e 00 74 00 42 00 65 00 6c 00 6f 00 77 00 } //1 DifferentBelow
		$a_01_4 = {42 00 65 00 63 00 61 00 75 00 73 00 65 00 42 00 69 00 67 00 } //1 BecauseBig
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_BazarLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 f6 74 0b 83 fe 01 75 0a 41 01 3c 91 eb 04 41 89 3c 91 41 8d 04 28 41 8b ce 03 f8 23 cd 41 8b c0 48 ff c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_BazarLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cd 03 d8 23 ce 41 8b c0 48 ff c2 0b c3 03 f0 41 8b c0 03 f1 33 c6 ff c0 03 e8 8b c6 33 c3 8b cd 44 03 c0 33 ce 44 03 c1 49 3b d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}