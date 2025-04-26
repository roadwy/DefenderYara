
rule Worm_Win32_Pricbot_A{
	meta:
		description = "Worm:Win32/Pricbot.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 07 8d 8d c8 fd ff ff 51 8d 8d ec fd ff ff e8 ?? ?? ff ff c6 45 fc 23 } //10
		$a_00_1 = {5b 61 75 74 6f 72 75 6e 5d } //10 [autorun]
		$a_00_2 = {50 61 73 73 70 6f 72 74 2e 4e 65 74 5c 2a } //1 Passport.Net\*
		$a_01_3 = {44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 DisableNotify
		$a_00_4 = {46 6c 6f 6f 64 20 73 74 61 72 74 65 64 } //1 Flood started
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}