
rule PWS_Win32_Magania_BQ{
	meta:
		description = "PWS:Win32/Magania.BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 3f 5d 3e a2 71 75 90 09 06 00 83 c7 04 83 e9 04 90 00 } //01 00 
		$a_03_1 = {81 7d 08 2e 62 6d 70 75 90 09 07 00 66 81 3f 4d 5a 75 90 00 } //01 00 
		$a_01_2 = {8b 55 08 32 e4 ac 32 02 2c 32 32 02 aa 42 fe c4 3a 65 0c } //02 00 
		$a_03_3 = {c7 85 b0 fe ff ff 01 00 00 00 ff b5 d0 fe ff ff ff 93 90 01 04 8d 8d d8 fe ff ff 51 ff b5 d4 fe ff ff ff 93 90 01 04 0b c0 0f 85 5f fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}