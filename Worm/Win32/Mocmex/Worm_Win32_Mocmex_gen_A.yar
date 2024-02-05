
rule Worm_Win32_Mocmex_gen_A{
	meta:
		description = "Worm:Win32/Mocmex.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 4b bb 01 00 00 00 8b 45 e4 e8 90 01 02 ff ff 50 8b c3 5a 8b ca 99 f7 f9 8b fa 47 8b 45 e4 0f b6 44 38 ff b9 0a 00 00 00 33 d2 f7 f1 8b 45 fc 0f b6 44 18 ff 33 d0 8d 45 dc e8 90 01 02 ff ff 8b 55 dc 8d 45 e0 e8 90 01 02 ff ff 43 4e 75 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}