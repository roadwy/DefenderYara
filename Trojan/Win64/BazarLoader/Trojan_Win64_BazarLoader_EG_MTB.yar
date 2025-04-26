
rule Trojan_Win64_BazarLoader_EG_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 24 20 0f b6 c0 83 e8 ?? 88 44 24 20 8a 44 24 20 0f b6 c0 8a 4c 24 21 0f b6 c9 0b c8 8b c1 88 44 24 21 8a 44 24 22 0f b6 c0 8a 4c 24 21 0f b6 c9 33 c8 8b c1 88 44 24 21 8a 44 24 22 fe c0 88 44 24 22 48 8b 44 24 30 8a 4c 24 21 88 08 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}