
rule Trojan_Win64_Iceid_PBF_MTB{
	meta:
		description = "Trojan:Win64/Iceid.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8b c1 3a db 90 13 b9 ?? ?? ?? ?? 48 f7 f1 3a c9 90 13 48 8b c2 48 8b 4c 24 ?? 3a c0 90 13 0f b6 44 01 ?? 8b 8c 24 ?? ?? ?? ?? 3a db 90 13 33 c8 8b c1 66 3b f6 90 13 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 90 13 88 04 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}