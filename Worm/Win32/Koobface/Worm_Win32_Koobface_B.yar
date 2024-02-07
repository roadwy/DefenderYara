
rule Worm_Win32_Koobface_B{
	meta:
		description = "Worm:Win32/Koobface.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {75 24 33 f6 81 c6 60 ea 00 00 81 fe 80 8d 5b 00 0f 8f e4 00 00 00 56 ff 15 90 01 02 40 00 e8 90 01 02 ff ff 84 c0 74 de 90 00 } //05 00 
		$a_01_1 = {c6 00 73 c6 40 01 2d c6 40 02 6b c6 40 03 61 c6 40 04 6b c6 40 05 61 c6 40 06 2e c6 40 00 6e c6 40 08 65 c6 40 09 74 c3 } //01 00 
		$a_00_2 = {2f 66 72 69 65 6e 64 73 2f 23 76 69 65 77 3d 65 76 65 72 79 6f 6e 65 } //01 00  /friends/#view=everyone
		$a_00_3 = {2f 69 6e 62 6f 78 2f 3f 63 6f 6d 70 6f 73 65 26 69 64 3d 25 73 } //01 00  /inbox/?compose&id=%s
		$a_00_4 = {46 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 20 00 7c 00 } //01 00  Facebook |
		$a_00_5 = {6e 00 65 00 77 00 2e 00 25 00 73 00 2f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 } //01 00  new.%s/profile.php?id=
		$a_00_6 = {25 00 73 00 2f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 } //00 00  %s/profile.php?id=
	condition:
		any of ($a_*)
 
}