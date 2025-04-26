
rule Ransom_Win32_Crypmod_B_bit{
	meta:
		description = "Ransom:Win32/Crypmod.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d0 80 e2 ?? 02 d2 02 d2 08 11 8b 0c 24 8a d0 d2 e2 8b 4c 24 ?? c0 e0 ?? 80 e2 ?? 08 11 8b 4c 24 ?? 08 01 } //1
		$a_03_1 = {8b 11 0f b6 0c 1a 8d 04 1a 0f b6 50 ?? 88 54 24 ?? 0f b6 50 ?? 88 4c 24 ?? 0f b6 48 [0-21] e8 ?? ?? ?? ?? 8a 44 24 ?? 0f b6 4c 24 ?? 0f b6 54 24 ?? 88 04 3e 46 88 0c 3e 46 88 14 3e 83 c3 ?? 46 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}