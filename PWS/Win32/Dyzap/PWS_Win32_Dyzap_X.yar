
rule PWS_Win32_Dyzap_X{
	meta:
		description = "PWS:Win32/Dyzap.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 87 00 04 00 00 ef be ad de c7 87 58 04 00 00 00 00 00 00 66 89 1f c7 47 3c 40 00 00 00 c7 47 40 50 45 00 00 } //01 00 
		$a_01_1 = {0f b6 2c 11 41 33 e8 81 e5 ff 00 00 00 c1 e8 08 33 04 ac 3b cb 7c e9 } //01 00 
		$a_03_2 = {8b c8 6a 2a e8 90 01 04 8b c8 6a 2e e8 90 01 04 8b c8 6a 65 e8 90 01 04 8b c8 6a 78 e8 90 01 04 8b c8 6a 65 90 00 } //01 00 
		$a_01_3 = {31 2c b8 47 3b fa 7c f8 } //00 00 
	condition:
		any of ($a_*)
 
}