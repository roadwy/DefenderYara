
rule Worm_Win32_Gexin_A{
	meta:
		description = "Worm:Win32/Gexin.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff ff 0b 8d 95 90 01 02 ff ff 33 c9 b8 90 01 04 e8 90 01 02 ff ff 8b 95 90 01 02 ff ff 8d 85 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff ba 90 01 04 8d 85 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 8d 85 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 8d 85 90 01 02 ff ff 33 c9 ba 44 00 00 00 e8 90 01 02 ff ff c7 85 90 01 02 ff ff 01 00 00 00 66 c7 85 90 01 02 ff ff 00 00 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 6a 00 6a 00 6a 40 6a 00 6a 00 6a 00 90 00 } //01 00 
		$a_02_1 = {33 c0 5a 59 59 64 89 10 68 90 01 04 8d 85 90 01 02 ff ff ba 03 00 00 00 e8 90 01 02 ff ff 8d 85 90 01 02 ff ff ba 02 00 00 00 e8 90 01 02 ff ff 8d 45 fc e8 90 01 02 ff ff c3 e9 90 01 02 ff ff eb d0 8b e5 5d c3 90 00 } //01 00 
		$a_00_2 = {43 68 65 63 6b 65 64 56 61 6c 75 65 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 30 20 2f 66 } //01 00 
		$a_00_3 = {43 68 65 63 6b 65 64 56 61 6c 75 65 20 2f 74 20 52 45 47 5f 64 77 6f 72 64 20 2f 64 20 30 30 30 30 30 30 30 32 20 2f 66 } //00 00 
	condition:
		any of ($a_*)
 
}