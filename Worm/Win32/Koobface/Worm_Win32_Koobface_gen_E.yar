
rule Worm_Win32_Koobface_gen_E{
	meta:
		description = "Worm:Win32/Koobface.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 63 63 6f 75 6e 74 20 73 65 63 75 74 69 72 79 } //01 00  account secutiry
		$a_01_1 = {63 61 70 74 63 68 61 20 69 6e 63 6f 72 72 65 63 74 } //01 00  captcha incorrect
		$a_01_2 = {25 73 3f 61 63 74 25 73 65 6e 26 76 3d 25 73 26 62 61 6e 5f 75 72 6c } //01 00  %s?act%sen&v=%s&ban_url
		$a_01_3 = {64 75 6d 70 20 72 65 73 70 6f 6e 63 65 } //00 00  dump responce
	condition:
		any of ($a_*)
 
}