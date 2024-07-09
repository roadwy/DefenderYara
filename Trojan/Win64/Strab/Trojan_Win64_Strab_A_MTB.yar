
rule Trojan_Win64_Strab_A_MTB{
	meta:
		description = "Trojan:Win64/Strab.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c0 41 f7 ea 44 01 c2 c1 fa 05 44 89 c0 c1 f8 1f 29 c2 6b d2 ?? 44 89 c0 29 d0 48 63 d0 48 8b 0d ?? ?? ?? ?? 0f b6 14 11 42 32 94 04 ?? ?? ?? ?? 43 88 14 01 49 83 c0 01 4d 39 d8 75 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}