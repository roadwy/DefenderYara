
rule Rogue_Win32_Therlowindo_A{
	meta:
		description = "Rogue:Win32/Therlowindo.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 25 73 26 73 75 62 49 44 30 3d 25 64 26 6d 69 64 3d 25 73 26 75 73 65 72 5f 69 70 3d 25 73 26 77 69 6e 3d 25 73 26 4c 54 69 6d 65 3d 25 6c 6c 64 26 61 76 3d 25 73 } //1 =%s&subID0=%d&mid=%s&user_ip=%s&win=%s&LTime=%lld&av=%s
		$a_01_1 = {00 5f 41 6e 74 69 56 69 72 75 73 3a 00 } //1
		$a_01_2 = {5c 4d 69 73 68 65 6c 5f 4d 6f 76 69 65 64 65 61 5c } //1 \Mishel_Moviedea\
		$a_01_3 = {2e 3f 41 56 43 4d 6f 6e 65 74 69 7a 65 54 68 72 65 61 64 40 40 } //1 .?AVCMonetizeThread@@
		$a_01_4 = {41 00 62 00 6f 00 75 00 74 00 20 00 57 00 69 00 6e 00 64 00 6f 00 57 00 65 00 61 00 74 00 68 00 65 00 72 00 } //10 About WindoWeather
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=13
 
}