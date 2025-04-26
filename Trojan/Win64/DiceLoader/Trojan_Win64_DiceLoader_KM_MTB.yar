
rule Trojan_Win64_DiceLoader_KM_MTB{
	meta:
		description = "Trojan:Win64/DiceLoader.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {49 63 d1 48 8b 08 42 8a 84 32 ?? ?? ?? ?? 42 32 44 11 ?? 43 88 04 22 41 8d 41 ?? 4c 63 c8 49 ff c2 48 b8 11 42 08 21 84 10 42 08 49 f7 e1 49 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 1f 4c 2b c8 4d 3b d0 7c } //1
		$a_02_1 = {49 63 c0 8a 84 38 ?? ?? ?? ?? 41 32 01 43 88 44 0a ?? 49 ff c1 41 ff c0 b8 43 08 21 84 41 f7 e8 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1f 44 2b c0 41 83 eb 01 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}