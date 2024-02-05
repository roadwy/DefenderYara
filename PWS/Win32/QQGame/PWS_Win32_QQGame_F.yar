
rule PWS_Win32_QQGame_F{
	meta:
		description = "PWS:Win32/QQGame.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 c7 06 d8 07 ff 15 90 01 04 66 83 7e 02 90 01 01 72 07 66 83 7e 06 90 01 01 73 4d 90 00 } //01 00 
		$a_03_1 = {68 e3 01 00 00 68 3c 02 00 00 68 c8 00 00 00 8b f1 68 2c 01 00 00 e8 90 01 04 8b 46 20 6a ec 90 00 } //01 00 
		$a_01_2 = {bb 01 00 00 00 81 c2 42 ff ff ff 53 68 9f 00 00 00 68 00 01 00 00 05 fe fe ff ff 52 50 8b cd e8 } //03 00 
		$a_03_3 = {6a 04 52 68 4b e1 22 00 50 ff 15 90 01 04 85 c0 74 10 ff 15 90 01 04 85 c0 75 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}