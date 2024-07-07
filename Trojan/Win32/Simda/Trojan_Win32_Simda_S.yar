
rule Trojan_Win32_Simda_S{
	meta:
		description = "Trojan:Win32/Simda.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 43 3c 03 c3 0f b7 48 14 8d 54 01 18 0f b7 40 06 8b 4a 14 03 4a 10 } //1
		$a_01_1 = {83 63 58 00 b8 00 20 00 00 66 09 43 16 } //1
		$a_01_2 = {77 76 3d 25 73 26 75 69 64 3d 25 64 26 6c 6e 67 3d 25 73 26 6d 69 64 3d 25 73 26 72 65 73 3d 25 73 } //1 wv=%s&uid=%d&lng=%s&mid=%s&res=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}