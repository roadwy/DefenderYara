
rule Trojan_Win32_Cinmus_O{
	meta:
		description = "Trojan:Win32/Cinmus.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 66 69 64 3d 25 64 26 6b 69 64 3d 25 64 26 61 69 64 3d 25 64 26 6d 61 63 3d 25 73 26 6b 77 3d 25 73 } //2 %s?fid=%d&kid=%d&aid=%d&mac=%s&kw=%s
		$a_01_1 = {68 70 6f 70 63 6f 75 6e 74 00 } //1 灨灯潣湵t
		$a_01_2 = {61 63 70 69 64 69 73 6b 00 } //1
		$a_01_3 = {6d 70 72 6d 73 67 73 65 2e 61 78 7a } //1 mprmsgse.axz
		$a_01_4 = {6f 72 67 5f 6d 64 35 3d 25 73 2c 20 63 61 6c 75 5f 6d 64 35 3d 25 73 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}