
rule Trojan_Win64_Injuke_GHM_MTB{
	meta:
		description = "Trojan:Win64/Injuke.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 08 48 ff c0 48 89 44 24 08 48 8b 44 24 28 48 39 44 24 08 ?? ?? 33 d2 48 8b 44 24 08 48 f7 74 24 38 48 8b c2 48 8b 4c 24 30 0f b6 04 01 48 8b 4c 24 08 48 8b 54 24 20 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 08 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}