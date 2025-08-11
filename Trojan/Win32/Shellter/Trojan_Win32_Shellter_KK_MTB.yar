
rule Trojan_Win32_Shellter_KK_MTB{
	meta:
		description = "Trojan:Win32/Shellter.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b f5 40 3b f2 79 ?? 48 c1 e6 04 2b fc 23 f5 ff c9 75 } //8
		$a_03_1 = {c1 e2 15 01 1d ?? ?? ?? ?? 2b f9 31 05 ?? ?? ?? ?? 33 d0 c1 c7 0a 8b fe c1 e0 13 2b 1d ?? ?? ?? ?? 81 ef 05 d7 e1 f4 01 05 ?? ?? ?? ?? 81 ca ad bb ec 35 bf c2 fc 9c df 81 f9 1a 29 9a 0b 7c ?? ?? ?? ?? ?? ?? ?? ?? c1 cb 10 33 d1 ff c9 75 } //7
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*7) >=15
 
}