
rule Trojan_Win64_EmotetPacker_AY_MTB{
	meta:
		description = "Trojan:Win64/EmotetPacker.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c8 99 44 8b 4d ?? 41 f7 f9 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d ?? ?? ?? ?? 4c 63 55 ?? 46 88 1c 11 8b 45 ?? 83 c0 01 89 45 ?? 90 13 8b 45 ?? 3b 45 ?? 73 ?? b8 ?? ?? ?? ?? 48 8b ?? ?? 48 63 ?? ?? 44 0f b6 04 11 48 8b 8d ?? ?? ?? ?? 44 8b 4d ?? 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}