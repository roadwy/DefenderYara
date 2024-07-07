
rule PWS_Win32_OnLineGames_IJ_dll{
	meta:
		description = "PWS:Win32/OnLineGames.IJ!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 25 73 25 64 2e 67 69 66 } //1 %s\%s%d.gif
		$a_01_1 = {6d 69 62 61 6f 73 68 6f 75 } //1 mibaoshou
		$a_01_2 = {4a 4d 56 5f 56 4d 4a } //1 JMV_VMJ
		$a_01_3 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 37 64 38 33 63 38 32 37 37 30 38 38 63 } //1 -----------------------------7d83c8277088c
		$a_01_4 = {2f 70 6f 62 61 6f 2f 47 65 74 54 75 50 69 61 6e 2e 61 73 70 } //1 /pobao/GetTuPian.asp
		$a_01_5 = {b5 d8 cf c2 b3 c7 d3 eb d3 c2 ca bf } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}