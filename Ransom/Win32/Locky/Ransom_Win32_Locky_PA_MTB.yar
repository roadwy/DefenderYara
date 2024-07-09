
rule Ransom_Win32_Locky_PA_MTB{
	meta:
		description = "Ransom:Win32/Locky.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 d0 33 c9 83 e9 01 23 4d ?? 03 c1 32 d2 fe ca 32 55 ?? f6 d2 8b f8 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 32 45 ?? 88 07 32 45 ?? 80 37 eb } //1
		$a_03_1 = {8a 00 02 45 ?? 89 7d ?? 0f b6 c0 89 45 ?? 0f af d7 03 ca 89 0d ?? ?? ?? 00 8b 45 ?? 0b 45 ?? 33 45 ?? f7 d0 33 c9 83 e9 01 23 4d ?? 03 c1 32 d2 fe ca 32 55 ?? f6 d2 8b f8 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 32 45 ?? 88 07 32 45 ?? 80 37 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}