
rule PWS_Win32_Zbot_gen_E{
	meta:
		description = "PWS:Win32/Zbot.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0d 00 00 ffffffff ffffffff "
		
	strings :
		$a_00_0 = {2e 64 61 74 61 00 } //fe ff 
		$a_00_1 = {00 2e 74 65 78 74 00 } //ff ff 
		$a_00_2 = {2e 72 65 6c 6f 63 00 } //ff ff 
		$a_00_3 = {2e 72 73 72 63 00 } //02 00 
		$a_03_4 = {c1 ea 08 41 83 f9 04 75 0a ba 90 01 04 b9 00 00 00 00 81 90 01 03 41 00 72 db 40 3d 15 27 00 00 76 c7 90 09 18 00 33 c0 ba 90 01 04 33 90 01 04 41 00 3d 0f 27 00 00 75 02 28 90 00 } //02 00 
		$a_03_5 = {75 02 28 10 40 c1 ea 08 47 83 ff 04 75 0a ba 90 01 04 bf 00 00 00 00 3d 90 01 02 40 00 72 db 41 81 f9 90 01 02 00 00 76 c6 90 09 14 00 33 c9 ba 90 01 04 33 ff b8 90 01 02 40 00 81 f9 90 01 02 00 00 90 00 } //02 00 
		$a_03_6 = {75 02 28 13 43 c1 ea 08 47 83 ff 04 75 0a 90 01 05 bf 00 00 00 00 81 fb 90 01 02 41 00 72 da 41 81 f9 90 01 02 00 00 76 c5 90 09 14 00 33 c9 90 01 05 33 ff 90 01 03 41 00 81 f9 0f 27 00 00 90 00 } //02 00 
		$a_03_7 = {75 02 28 07 47 c1 e8 08 41 83 f9 04 75 0a b8 90 01 04 b9 00 00 00 00 81 ff 90 01 02 40 00 72 da 43 81 fb 90 01 02 00 00 76 c5 90 09 14 00 33 db b8 90 01 04 33 c9 bf 90 01 02 40 00 81 fb 90 01 02 00 00 90 00 } //02 00 
		$a_03_8 = {75 02 28 07 47 c1 e8 08 42 83 fa 04 75 0a b8 90 01 04 ba 00 00 00 00 81 ff 90 01 02 41 00 72 da 41 81 f9 90 01 02 00 00 76 c5 90 09 14 00 33 c9 b8 90 01 04 33 d2 bf 90 01 02 41 00 81 f9 90 01 02 00 00 90 00 } //02 00 
		$a_03_9 = {75 02 28 01 41 c1 e8 08 42 83 fa 04 75 0a b8 90 01 04 ba 00 00 00 00 81 f9 90 01 02 41 00 72 da 47 81 ff 90 01 02 00 00 76 c5 90 09 14 00 33 ff b8 90 01 04 33 d2 b9 90 01 02 41 00 81 ff 90 01 02 00 00 90 00 } //02 00 
		$a_02_10 = {75 02 28 03 43 c1 e8 08 41 83 f9 04 75 0a b8 90 01 04 b9 00 00 00 00 81 fb 90 01 02 41 00 72 da 47 81 ff 90 01 02 00 00 76 c5 90 09 14 00 33 ff b8 90 01 04 33 c9 bb 90 01 02 41 00 81 ff 90 01 02 00 00 90 00 } //02 00 
		$a_02_11 = {75 02 28 18 40 c1 eb 08 41 83 f9 04 75 0a 90 01 06 00 00 00 00 90 01 03 41 00 72 db 47 81 ff 90 01 02 00 00 76 c6 90 90 00 14 00 33 ff 90 01 05 33 90 01 04 41 00 81 ff 0f 27 00 00 90 00 } //02 00 
		$a_03_12 = {75 02 28 10 40 c1 ea 08 41 83 f9 04 75 0a 90 01 06 00 00 00 00 90 01 03 41 00 72 db 47 81 ff 90 01 02 00 00 76 c6 90 09 14 00 33 ff 90 01 05 33 90 01 04 41 00 81 ff 0f 27 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}