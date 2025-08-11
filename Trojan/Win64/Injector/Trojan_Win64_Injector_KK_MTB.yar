
rule Trojan_Win64_Injector_KK_MTB{
	meta:
		description = "Trojan:Win64/Injector.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c1 48 8b d0 8b c0 48 c1 ea ?? 48 33 d0 41 83 e0 ?? 48 8b c2 49 33 c1 41 be ?? 00 00 00 48 35 ?? ?? ?? ?? 41 8b ce 48 c1 e8 08 41 2a c8 48 33 c2 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}