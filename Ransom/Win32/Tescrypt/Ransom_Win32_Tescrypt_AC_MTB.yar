
rule Ransom_Win32_Tescrypt_AC_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 89 45 ?? 2b f9 25 ?? ?? ?? ?? 8b c7 8d 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? 8b c7 c1 e8 ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 03 c7 50 8b 45 ?? 03 c3 e8 ?? ?? ?? ?? 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 83 25 ?? ?? ?? ?? ?? 2b 75 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 ?? 89 78 ?? 5f 89 30 5e 5b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}