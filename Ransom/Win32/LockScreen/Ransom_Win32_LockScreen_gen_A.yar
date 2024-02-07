
rule Ransom_Win32_LockScreen_gen_A{
	meta:
		description = "Ransom:Win32/LockScreen.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 8b 40 08 81 38 54 44 53 de 0f 85 f0 02 00 00 8b 45 fc 80 b8 9e 00 00 00 00 0f 84 e0 02 00 00 8b 45 fc 83 b8 a0 00 00 00 00 75 7b ba 00 80 00 00 b8 90 01 04 e8 90 01 04 8b d8 8b 45 fc 89 98 a0 00 00 00 85 db 74 42 8b 45 f8 90 00 } //01 00 
		$a_00_1 = {34 39 36 38 35 37 36 31 } //01 00  49685761
		$a_00_2 = {30 36 31 35 39 32 33 30 } //01 00  06159230
		$a_00_3 = {70 6c 75 67 69 6e } //00 00  plugin
	condition:
		any of ($a_*)
 
}