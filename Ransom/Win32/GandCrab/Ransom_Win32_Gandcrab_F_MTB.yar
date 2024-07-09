
rule Ransom_Win32_Gandcrab_F_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {eb 06 8d 9b 00 00 00 00 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b d1 c1 ea 10 30 14 30 40 3b c7 7c e7 89 0d } //1
		$a_00_1 = {64 a1 2c 00 00 00 8b 08 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 c7 41 04 01 00 00 00 e8 } //1
		$a_02_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 0e ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 06 8b 0d ?? ?? ?? ?? 46 3b f1 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}