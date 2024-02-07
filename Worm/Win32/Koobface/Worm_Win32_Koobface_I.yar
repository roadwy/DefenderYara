
rule Worm_Win32_Koobface_I{
	meta:
		description = "Worm:Win32/Koobface.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {c8 01 00 00 6a 01 ff d6 ff 4c 24 20 75 f6 } //02 00 
		$a_01_1 = {26 63 6b 3d 25 64 26 63 5f 66 62 3d 25 64 26 63 5f 6d 73 3d 25 64 26 63 5f 68 69 3d 25 64 26 63 5f 62 65 3d 25 64 26 63 5f 66 72 3d 25 64 26 63 5f 79 62 3d 25 64 } //01 00  &ck=%d&c_fb=%d&c_ms=%d&c_hi=%d&c_be=%d&c_fr=%d&c_yb=%d
		$a_01_2 = {46 42 54 41 52 47 45 54 50 45 52 50 4f 53 54 } //01 00  FBTARGETPERPOST
		$a_01_3 = {46 42 53 48 41 52 45 55 52 4c } //01 00  FBSHAREURL
		$a_01_4 = {23 42 4c 41 43 4b 4c 41 42 45 4c } //01 00  #BLACKLABEL
		$a_01_5 = {25 73 5c 74 74 5f 25 64 2e 65 78 65 } //01 00  %s\tt_%d.exe
		$a_01_6 = {2f 61 63 68 63 68 65 63 6b 2e 70 68 70 } //00 00  /achcheck.php
	condition:
		any of ($a_*)
 
}