
rule PWS_Win32_QQThief_D{
	meta:
		description = "PWS:Win32/QQThief.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 00 00 00 40 47 66 c7 43 04 b2 d7 74 0b b8 00 00 00 80 66 c7 43 04 b1 d7 6a 00 68 80 00 00 00 51 6a 00 52 50 8d 43 48 50 e8 } //01 00 
		$a_03_1 = {83 f8 07 75 1c 6a 01 e8 90 01 02 ff ff 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 02 b3 01 8b c3 5b c3 90 00 } //01 00 
		$a_01_2 = {7c 6d 72 61 64 6d 69 6e 7c 00 } //01 00 
		$a_01_3 = {73 65 74 74 65 6c 6c 6f 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}