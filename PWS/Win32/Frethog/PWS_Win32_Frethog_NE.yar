
rule PWS_Win32_Frethog_NE{
	meta:
		description = "PWS:Win32/Frethog.NE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 4c 6f 63 6b 23 53 65 63 75 72 69 74 79 23 3d } //1 #Lock#Security#=
		$a_01_1 = {75 69 64 3d 25 64 26 7a 69 64 3d 25 64 26 63 69 64 3d 25 64 26 67 69 64 3d 25 73 26 74 6f 6b 65 6e 3d 25 73 } //1 uid=%d&zid=%d&cid=%d&gid=%s&token=%s
		$a_01_2 = {26 70 72 6f 63 65 73 73 62 3d 25 73 26 70 72 6f 63 65 73 73 3d 25 73 } //1 &processb=%s&process=%s
		$a_01_3 = {78 68 74 6d 6c 2e 70 68 70 3f 74 6f 6b 65 6e 3d 30 78 41 42 43 44 } //1 xhtml.php?token=0xABCD
		$a_01_4 = {8d 3c 02 33 f7 2b ce 8b 75 ec 81 c2 47 86 c8 61 85 f6 7f bd } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}