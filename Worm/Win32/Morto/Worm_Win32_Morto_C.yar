
rule Worm_Win32_Morto_C{
	meta:
		description = "Worm:Win32/Morto.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 32 74 17 8b 85 90 01 02 ff ff 0f be 00 8b 8d 90 01 02 ff ff 03 c8 90 00 } //01 00 
		$a_03_1 = {66 81 3f 8b ff 75 90 14 90 09 02 00 47 47 90 00 } //02 00 
		$a_01_2 = {8b 45 f8 8a 4d 10 03 c6 28 08 46 3b 75 0c 72 } //01 00 
		$a_03_3 = {53 59 53 54 c7 45 90 01 01 45 4d 5c 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}