
rule Ransom_Win32_Spora_C_bit{
	meta:
		description = "Ransom:Win32/Spora.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 08 57 8b 7d 0c e8 70 ff ff ff 30 04 3e 5f 5e 5d c2 08 00 } //01 00 
		$a_03_1 = {41 81 e1 ff 00 00 00 56 8b 34 8d 90 01 02 00 01 03 c6 25 ff 00 00 00 8a 14 85 90 01 02 00 01 0f b6 d2 90 00 } //01 00 
		$a_03_2 = {00 01 89 14 8d 90 01 02 00 01 89 0d 90 01 02 00 01 8b 0c 85 90 01 02 00 01 03 ca 81 e1 ff 00 00 00 a3 90 01 02 00 01 8a 04 8d 90 01 02 00 01 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}