
rule PWS_Win32_Zbot_gen_L{
	meta:
		description = "PWS:Win32/Zbot.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 ffffffff ffffffff "
		
	strings :
		$a_00_0 = {2e 64 61 74 61 00 } //fe ff 
		$a_00_1 = {00 2e 74 65 78 74 00 } //ff ff 
		$a_00_2 = {2e 72 65 6c 6f 63 00 } //ff ff 
		$a_00_3 = {2e 72 73 72 63 00 } //02 00 
		$a_03_4 = {60 87 c9 50 9c 81 d0 90 01 04 b8 90 01 04 b8 90 01 04 9d 58 33 c0 8d 48 0a 50 49 0f 85 f8 ff ff ff 74 00 8b ec 9c 51 03 c9 81 f1 90 01 04 59 9d 9c 52 8b c0 52 5a eb 01 90 01 01 5a 9d 64 8b 40 30 8b d2 9c 50 57 9c 54 5c bf 90 01 04 52 9c 81 ea 90 01 04 9d 5a 9d 5f 81 d0 90 01 04 58 9d 0f 88 90 01 01 00 00 00 eb 01 90 01 01 87 e4 8b 40 0c eb 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}