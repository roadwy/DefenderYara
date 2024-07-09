
rule Trojan_Win64_Raccoon_CBVV_MTB{
	meta:
		description = "Trojan:Win64/Raccoon.CBVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 48 98 0f b6 44 04 70 48 63 4c 24 2c 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 0a 33 c8 8b c1 48 63 4c 24 2c 48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}