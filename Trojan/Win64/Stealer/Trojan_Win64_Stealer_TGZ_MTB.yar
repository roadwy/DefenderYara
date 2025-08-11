
rule Trojan_Win64_Stealer_TGZ_MTB{
	meta:
		description = "Trojan:Win64/Stealer.TGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 48 8b 8c 24 b8 ab 00 00 66 89 01 8b 84 24 68 1a 00 00 48 8b 8c 24 50 48 00 00 48 8b 49 08 8b 94 24 98 71 00 00 48 8b bc 24 00 e4 00 00 0f b6 04 08 88 04 17 8b 84 24 ?? ?? ?? ?? ff c0 89 84 24 ?? ?? ?? ?? 8b 84 24 54 7e 00 00 8b 8c 24 d8 71 00 00 2b c8 8b c1 89 84 24 a8 71 00 00 8b 84 24 20 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}