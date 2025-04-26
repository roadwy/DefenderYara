
rule Worm_Win32_Nuwar_KA{
	meta:
		description = "Worm:Win32/Nuwar.KA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec [0-f0] 8b 45 ?? 8b 40 ?? 89 45 ?? 8b 45 ?? 8b 40 ?? 89 45 [0-40] 83 7d ?? 00 75 90 90 00 [0-50] c7 45 ?? b9 79 37 9e [0-18] 6a 34 58 99 [0-28] 69 c0 b9 79 37 9e } //1
		$a_02_1 = {c1 e8 05 8b 4d ?? c1 e1 02 33 c1 8b 4d ?? c1 e9 03 8b 55 ?? c1 e2 04 33 ca 03 c1 8b 4d ?? 33 4d ?? 8b 55 ?? 83 e2 03 33 55 ?? 8b 75 ?? 8b 14 96 33 55 ?? 03 ca 33 c1 8b 4d [0-48] e9 ?? ff ff ff } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}