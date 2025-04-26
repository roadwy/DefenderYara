
rule Worm_Win32_Dorpiex_B{
	meta:
		description = "Worm:Win32/Dorpiex.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {80 3b 21 0f 85 ?? ?? 00 00 8b 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 40 89 85 ?? ?? ff ff 03 c0 03 c0 } //3
		$a_00_1 = {26 63 6c 69 65 6e 74 3d 6d 65 72 63 75 72 79 26 5f 5f 75 73 65 72 3d 25 73 26 5f 5f 61 3d 31 } //2 &client=mercury&__user=%s&__a=1
		$a_00_2 = {73 65 6c 65 63 74 20 6e 61 6d 65 2c 20 76 61 6c 75 65 20 66 72 6f 6d 20 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 20 77 68 65 72 65 20 68 6f 73 74 20 6c 69 6b 65 20 27 25 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 27 } //1 select name, value from moz_cookies where host like '%.facebook.com'
		$a_01_3 = {7b 65 6e 64 7d 00 } //1 敻摮}
		$a_00_4 = {5c 62 6f 74 5c 66 62 73 5c } //1 \bot\fbs\
		$a_01_5 = {54 5a 61 70 43 6f 6d 6d 75 6e 69 63 61 74 6f 72 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}