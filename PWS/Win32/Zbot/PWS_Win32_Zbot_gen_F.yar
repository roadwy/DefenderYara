
rule PWS_Win32_Zbot_gen_F{
	meta:
		description = "PWS:Win32/Zbot.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 ffffffff ffffffff "
		
	strings :
		$a_00_0 = {2e 64 61 74 61 00 } //fe ff  搮瑡a
		$a_00_1 = {00 2e 74 65 78 74 00 } //ff ff 
		$a_00_2 = {2e 72 65 6c 6f 63 00 } //ff ff 
		$a_00_3 = {2e 72 73 72 63 00 } //02 00  爮牳c
		$a_03_4 = {55 8b ec 83 ec 90 01 01 33 90 01 01 89 90 01 01 24 90 01 06 33 90 01 01 bf 90 01 02 41 00 89 7c 24 90 01 01 81 7c 24 90 01 03 00 00 75 06 8b 54 24 90 01 01 28 90 01 01 ff 44 24 90 01 01 c1 90 01 01 08 90 01 01 83 90 01 01 04 75 0a 90 01 06 00 00 00 00 bf 90 01 02 41 00 39 7c 24 90 01 01 72 ce ff 44 24 90 01 01 81 7c 24 90 01 03 00 00 76 b0 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}