
rule Trojan_Win64_CobaltStrike_GYZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 8a c0 41 ff c0 2a c1 04 ?? 41 30 01 49 ff c1 41 83 f8 ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}