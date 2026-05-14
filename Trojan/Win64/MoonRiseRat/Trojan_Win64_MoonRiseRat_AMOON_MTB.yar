
rule Trojan_Win64_MoonRiseRat_AMOON_MTB{
	meta:
		description = "Trojan:Win64/MoonRiseRat.AMOON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 6d 00 48 8b 54 24 50 48 89 94 24 e0 01 00 00 48 8b 74 24 30 48 89 b4 24 e8 01 00 00 4c 8d 05 e7 84 07 00 4c 89 84 24 f0 01 00 00 48 c7 84 24 f8 01 00 00 ?? ?? ?? ?? 4c 8d 0d 84 84 07 00 4c 89 8c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}