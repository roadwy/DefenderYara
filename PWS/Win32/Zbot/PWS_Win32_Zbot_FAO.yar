
rule PWS_Win32_Zbot_FAO{
	meta:
		description = "PWS:Win32/Zbot.FAO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {ab ab ab ab 66 ab c6 90 01 02 6b c6 90 01 02 65 c6 90 01 02 72 c6 90 01 02 6e c6 90 01 02 65 c6 90 01 02 6c c6 90 01 02 33 c6 90 01 02 32 c6 90 01 02 2e c6 90 01 02 64 c6 90 01 02 6c c6 90 01 02 6c 80 90 01 02 00 c6 90 01 02 57 c6 90 01 02 69 c6 90 01 02 6e c6 90 01 02 45 c6 90 01 02 78 c6 90 01 02 65 c6 90 01 02 63 90 00 } //02 00 
		$a_03_1 = {83 c4 0c c6 90 01 03 ff ff 47 c6 90 01 03 ff ff 45 c6 90 01 03 ff ff 54 c6 90 01 03 ff ff 20 90 02 25 ff ff 2f c6 90 01 03 ff ff 73 c6 90 01 03 ff ff 63 c6 90 01 03 ff ff 72 c6 90 01 03 ff ff 69 c6 90 01 03 ff ff 70 c6 90 01 03 ff ff 74 c6 90 01 03 ff ff 73 c6 90 01 03 ff ff 2f c6 90 01 03 ff ff 67 c6 90 01 03 ff ff 65 c6 90 01 03 ff ff 74 c6 90 01 03 ff ff 5f c6 90 01 03 ff ff 63 c6 90 01 03 ff ff 6f c6 90 01 03 ff ff 6d c6 90 01 03 ff ff 6d c6 90 01 03 ff ff 61 c6 90 01 03 ff ff 6e c6 90 01 03 ff ff 64 c6 90 01 03 ff ff 2e c6 90 01 03 ff ff 70 c6 90 01 03 ff ff 68 c6 90 01 03 ff ff 70 c6 90 01 03 ff ff 3f c6 90 01 03 ff ff 6e c6 90 01 03 ff ff 61 c6 90 01 03 ff ff 6d c6 90 01 03 ff ff 65 c6 90 01 03 ff ff 3d 90 00 } //01 00 
		$a_00_2 = {47 45 54 20 2f 73 63 72 69 70 74 73 2f 67 65 74 5f 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 6e 61 6d 65 3d } //01 00 
		$a_00_3 = {67 61 6d 75 6e 6b 75 6c 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}