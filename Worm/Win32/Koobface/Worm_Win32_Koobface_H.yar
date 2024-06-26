
rule Worm_Win32_Koobface_H{
	meta:
		description = "Worm:Win32/Koobface.H,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {b8 10 2b 00 00 e8 90 01 03 00 55 56 ff 15 90 01 03 00 99 b9 0a 00 00 00 90 02 10 f7 f9 90 02 10 52 ff d5 90 00 } //03 00 
		$a_03_1 = {f2 ae f7 d1 49 03 d1 3b f2 72 bd ff 15 90 01 04 33 d2 b9 0a 00 00 00 f7 f1 52 ff d5 5f 5b 5e 5d 90 00 } //03 00 
		$a_03_2 = {56 ff d5 83 c4 04 33 ff 56 ff d5 83 c4 04 85 c0 0f 85 90 01 02 00 00 47 81 ff 58 02 00 00 7c e9 56 90 00 } //01 00 
		$a_01_3 = {25 73 2f 66 72 69 65 6e 64 73 2f 3f 76 69 65 77 3d } //01 00  %s/friends/?view=
		$a_01_4 = {72 65 63 61 70 74 63 68 61 5f 69 6d 61 67 65 } //01 00  recaptcha_image
		$a_01_5 = {63 61 70 74 63 68 61 5f 73 75 62 6d 69 74 } //01 00  captcha_submit
		$a_01_6 = {46 42 53 48 41 52 45 55 52 4c } //01 00  FBSHAREURL
		$a_01_7 = {46 42 54 41 52 47 45 54 } //00 00  FBTARGET
	condition:
		any of ($a_*)
 
}