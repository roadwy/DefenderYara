
rule Trojan_Win64_Graftor_B_MTB{
	meta:
		description = "Trojan:Win64/Graftor.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 23 d1 80 da ?? 44 33 c7 41 f7 d8 c0 e2 ?? 48 81 f2 ?? ?? ?? ?? 41 81 f0 ?? ?? ?? ?? 41 0f c8 } //2
		$a_03_1 = {d2 f8 66 45 0b f1 41 57 44 0f c0 d5 66 45 33 d0 48 83 ec ?? 4d 0f a3 f8 4c 8b 79 ?? 48 8b c1 49 0f ab e2 8b 49 ?? c1 df a4 41 c0 f2 bd 2b ?? 41 b2 ?? 66 41 0f c8 4c 8b c2 41 c0 c6 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*4) >=6
 
}