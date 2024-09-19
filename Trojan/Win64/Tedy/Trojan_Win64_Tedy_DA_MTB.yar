
rule Trojan_Win64_Tedy_DA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 08 0f b6 0c 11 2b c1 05 00 01 00 00 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 48 8b 0c 24 48 8b 54 24 28 48 03 d1 48 8b ca 88 01 48 8b 44 24 08 48 ff c0 33 d2 b9 08 00 00 00 48 f7 f1 48 8b c2 48 89 44 24 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}