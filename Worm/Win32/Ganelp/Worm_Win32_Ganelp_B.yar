
rule Worm_Win32_Ganelp_B{
	meta:
		description = "Worm:Win32/Ganelp.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 41 65 74 63 72 65 6f 64 73 47 72 64 73 00 } //01 00 
		$a_00_1 = {6e 32 6c 72 33 6c 65 6c 64 6b 65 2e 00 } //01 00 
		$a_00_2 = {62 72 6f 46 6c 6c 65 47 61 65 00 } //01 00 
		$a_00_3 = {62 6c 6f 41 63 6c 6c 6f 47 61 6c 00 } //01 00 
		$a_00_4 = {46 53 74 65 65 65 6c 7a 47 69 69 00 } //01 00 
		$a_00_5 = {61 6f 65 32 70 74 65 54 68 33 61 6f 72 65 6c 70 6e 68 43 74 6f 6c 53 73 00 } //06 00 
		$a_03_6 = {8b f4 8b 95 d0 fe ff ff 52 ff 15 90 01 04 3b f4 e8 90 01 04 89 85 cc fe ff ff 83 bd cc fe ff ff 02 0f 85 90 01 04 8d 85 54 fa ff ff 50 8b 8d d0 fe ff ff 51 e8 90 01 04 83 c4 08 89 85 c4 fe ff ff 8d 95 54 fa ff ff 89 95 50 fa ff ff 8b 85 d0 fe ff ff 50 8d 8d 60 fe ff ff 51 e8 76 1e 00 00 83 c4 08 6a 00 68 40 75 42 00 8d 95 54 fe ff ff 52 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}