
rule PWS_Win32_Magovel_A{
	meta:
		description = "PWS:Win32/Magovel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 54 3a ff 33 55 f8 e8 90 01 04 8b 55 f4 8b c6 e8 90 01 04 47 4b 75 df 90 00 } //01 00 
		$a_01_1 = {66 83 f8 03 74 06 66 83 f8 04 75 53 6a 32 } //01 00 
		$a_02_2 = {26 76 65 72 3d 90 09 04 00 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}