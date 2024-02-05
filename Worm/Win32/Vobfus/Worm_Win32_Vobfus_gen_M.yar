
rule Worm_Win32_Vobfus_gen_M{
	meta:
		description = "Worm:Win32/Vobfus.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {69 c0 aa 00 00 00 0f 80 90 01 04 89 45 90 01 01 c7 45 90 01 01 05 00 00 00 dd 05 90 01 04 51 51 90 00 } //05 00 
		$a_01_1 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //01 00 
		$a_01_2 = {50 66 b9 50 00 e8 } //01 00 
		$a_01_3 = {50 66 b9 58 00 e8 } //01 00 
		$a_01_4 = {50 66 b9 5b 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}