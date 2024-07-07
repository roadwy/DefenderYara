
rule PWS_Win32_Dozmot_E{
	meta:
		description = "PWS:Win32/Dozmot.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 06 8a 0f 32 d1 02 d1 32 c2 d2 c8 88 06 } //1
		$a_01_1 = {c6 04 02 e9 8b cb 2b ca 83 e9 05 } //1
		$a_01_2 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 73 } //1 %s?action=postmb&u=%s&mb=%s
		$a_01_3 = {26 66 69 64 3d 25 73 26 6c 65 76 3d 25 64 26 6a 62 3d 25 64 } //1 &fid=%s&lev=%d&jb=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}