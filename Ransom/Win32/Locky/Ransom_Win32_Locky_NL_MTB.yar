
rule Ransom_Win32_Locky_NL_MTB{
	meta:
		description = "Ransom:Win32/Locky.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 65 f8 76 ff d6 25 ?? ?? ?? ?? 0f af 45 f8 2b f8 0f af 7d ?? 8b 45 08 2b c7 89 45 f0 } //3
		$a_03_1 = {33 d2 8b c7 f7 f1 0f b6 4d ?? 33 d2 2b c8 8b 45 ec } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}