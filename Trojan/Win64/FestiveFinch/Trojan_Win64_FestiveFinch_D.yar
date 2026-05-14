
rule Trojan_Win64_FestiveFinch_D{
	meta:
		description = "Trojan:Win64/FestiveFinch.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 3d fc 12 00 00 [0-1e] 8b 0c 24 33 d2 8b 04 24 41 b8 08 00 00 00 41 f7 f0 8b c2 8b c0 0f b6 44 04 08 48 8b 54 24 10 0f b6 4c 0a 08 33 c8 8b c1 8b 0c 24 48 8d ?? ?? ?? ?? ?? 88 44 0a 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}