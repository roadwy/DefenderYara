
rule Ransom_Win32_CubaPacker_SA_MTB{
	meta:
		description = "Ransom:Win32/CubaPacker.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 b4 33 85 ?? ?? ?? ?? c1 c0 ?? 03 f0 89 5d ?? 89 75 ?? 89 75 ?? 33 f1 8b 4d ?? c1 c6 ?? 89 75 ?? 03 ce 89 75 ?? 8b 75 ?? 89 4d ?? 89 4d ?? 33 c8 c1 c1 ?? 83 6d ?? ?? 89 4d ?? 89 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}