
rule Worm_Win32_Dogkild_B{
	meta:
		description = "Worm:Win32/Dogkild.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 02 75 0d 8d 44 24 08 50 e8 90 01 02 ff ff 83 c4 04 fe c3 80 fb 7a 7e c7 90 00 } //01 00 
		$a_01_1 = {68 c8 00 00 00 51 68 0c 20 22 00 53 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}