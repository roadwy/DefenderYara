
rule Worm_Win32_Koobface_J{
	meta:
		description = "Worm:Win32/Koobface.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 7c 53 ff 15 90 01 04 8b f0 83 c4 08 3b f5 0f 84 90 01 02 00 00 68 90 01 04 c6 06 00 53 46 ff 15 90 00 } //1
		$a_01_1 = {6a 00 51 52 c7 44 24 24 3c 00 00 00 c7 44 24 38 63 00 00 00 ff 15 } //1
		$a_01_2 = {6e 69 63 6b 3d 25 73 26 6c 6f 67 69 6e 3d 25 73 26 73 75 63 63 65 73 73 3d 25 64 26 66 72 69 65 6e 64 73 3d 25 64 26 63 61 70 74 63 68 61 3d 25 64 26 66 69 6e 69 73 68 3d 25 64 26 76 3d 25 73 26 70 3d 25 73 26 63 3d 25 64 } //1 nick=%s&login=%s&success=%d&friends=%d&captcha=%d&finish=%d&v=%s&p=%s&c=%d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}