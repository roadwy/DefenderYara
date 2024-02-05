
rule Ransom_Win32_Shade_C_bit{
	meta:
		description = "Ransom:Win32/Shade.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 eb 00 eb 00 a1 90 01 03 00 a3 90 01 03 00 8b 0d 90 01 03 00 8b 11 89 15 90 01 03 00 a1 90 01 03 00 83 e8 0b a3 90 01 03 00 8b 15 90 01 03 00 83 c2 0b a1 90 01 03 00 8b ff 8b ca a3 90 01 03 00 31 0d 90 01 03 00 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 c7 45 fc 00 00 00 00 a1 90 01 03 00 03 05 90 01 03 00 0f b6 08 f7 d9 8b 15 90 01 03 00 03 15 90 01 03 00 0f b6 02 2b c1 8b 0d 90 01 03 00 03 0d 90 01 03 00 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}