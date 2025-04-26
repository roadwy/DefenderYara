
rule Ransom_Win32_Crypmod_A_bit{
	meta:
		description = "Ransom:Win32/Crypmod.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c6 0f b6 c9 2b c1 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 41 3b c1 7f 07 8b c6 a3 } //1
		$a_03_1 = {88 04 0a 0f b7 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 42 3b 55 ?? 0f 8c ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}