
rule Worm_Win32_Vobfus_gen_L{
	meta:
		description = "Worm:Win32/Vobfus.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {69 c0 aa 00 00 00 0f 80 90 01 04 89 85 90 01 04 db 85 90 00 } //02 00 
		$a_03_1 = {69 c0 ac 00 00 00 0f 80 90 01 04 89 85 90 01 04 db 85 90 00 } //01 00 
		$a_01_2 = {50 66 b9 58 00 e8 } //01 00 
		$a_01_3 = {50 66 b9 5b 00 e8 } //01 00 
		$a_01_4 = {50 66 b9 50 00 e8 } //01 00 
		$a_01_5 = {50 66 b9 c3 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}