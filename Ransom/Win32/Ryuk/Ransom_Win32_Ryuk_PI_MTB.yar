
rule Ransom_Win32_Ryuk_PI_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 4d ?? 81 ?? ?? ?? ?? 00 00 0f [0-05] 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 89 45 ?? 8b 4d ?? 81 ?? a3 00 00 00 89 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? f7 d0 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 81 ?? a3 00 00 00 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 81 ?? ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}