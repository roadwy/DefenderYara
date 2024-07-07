
rule Worm_Win32_Clisbot_A{
	meta:
		description = "Worm:Win32/Clisbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 d0 07 00 00 ff d6 e8 90 01 04 84 c0 74 11 68 10 27 00 00 ff d6 e8 90 01 04 e9 90 00 } //1
		$a_03_1 = {68 01 01 00 00 ff 15 90 01 04 b9 02 00 00 00 6a 35 66 89 4c 24 90 01 01 c7 44 24 90 01 01 00 00 00 00 ff 15 90 01 04 6a 11 6a 02 6a 02 66 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}