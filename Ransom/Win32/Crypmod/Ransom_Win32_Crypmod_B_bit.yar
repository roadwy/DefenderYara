
rule Ransom_Win32_Crypmod_B_bit{
	meta:
		description = "Ransom:Win32/Crypmod.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a d0 80 e2 90 01 01 02 d2 02 d2 08 11 8b 0c 24 8a d0 d2 e2 8b 4c 24 90 01 01 c0 e0 90 01 01 80 e2 90 01 01 08 11 8b 4c 24 90 01 01 08 01 90 00 } //01 00 
		$a_03_1 = {8b 11 0f b6 0c 1a 8d 04 1a 0f b6 50 90 01 01 88 54 24 90 01 01 0f b6 50 90 01 01 88 4c 24 90 01 01 0f b6 48 90 02 21 e8 90 01 04 8a 44 24 90 01 01 0f b6 4c 24 90 01 01 0f b6 54 24 90 01 01 88 04 3e 46 88 0c 3e 46 88 14 3e 83 c3 90 01 01 46 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}