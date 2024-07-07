
rule Trojan_Win64_CobaltStrike_RAZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 e1 83 0f 3e 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b d2 42 41 8b c0 2b c2 48 63 c8 42 0f b6 04 19 43 32 04 0a 41 88 01 41 ff c0 49 ff c1 41 81 f8 09 0e 04 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}