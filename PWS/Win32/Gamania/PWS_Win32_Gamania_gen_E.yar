
rule PWS_Win32_Gamania_gen_E{
	meta:
		description = "PWS:Win32/Gamania.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 90 01 04 8b 55 f4 8b c7 e8 90 01 04 ff 45 f8 4e 75 d9 90 00 } //01 00 
		$a_03_1 = {6a 00 8d 45 fc 50 68 01 04 00 00 8d 85 ef fb ff ff 50 56 e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}