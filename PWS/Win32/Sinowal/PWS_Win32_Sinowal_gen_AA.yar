
rule PWS_Win32_Sinowal_gen_AA{
	meta:
		description = "PWS:Win32/Sinowal.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 01 6a ff 68 00 08 00 00 68 } //05 00 
		$a_03_1 = {03 41 14 50 90 03 04 03 ff 75 08 5a 8b 55 08 90 00 } //01 00 
		$a_01_2 = {52 2b d2 42 0b d2 5a 75 00 } //01 00 
		$a_01_3 = {57 2b ff 47 0b ff 5f 75 00 } //01 00 
		$a_01_4 = {51 2b c9 41 0b c9 59 75 00 } //01 00 
		$a_01_5 = {8b 45 fc 83 c0 01 50 8f 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}