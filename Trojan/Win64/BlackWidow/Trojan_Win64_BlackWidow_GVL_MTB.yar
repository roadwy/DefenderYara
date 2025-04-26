
rule Trojan_Win64_BlackWidow_GVL_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 04 01 89 44 24 68 48 63 4c 24 50 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 58 88 04 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}