
rule Trojan_Win64_WingoObfus_AB_MTB{
	meta:
		description = "Trojan:Win64/WingoObfus.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 05 94 ed 06 00 46 0f b6 04 00 44 31 c2 88 14 1e 48 ff c3 48 89 f0 48 89 fa 48 39 d9 7e 34 48 89 c6 48 b8 25 ?? ?? ?? ?? ?? ?? ?? 48 89 d7 48 f7 eb 48 d1 fa 4c 8d 04 52 4a 8d 14 42 48 89 d8 48 29 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}