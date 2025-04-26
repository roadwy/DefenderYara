
rule PWS_Win32_Frethog_MV{
	meta:
		description = "PWS:Win32/Frethog.MV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 38 23 23 23 23 75 } //1
		$a_01_1 = {8d 0c 38 83 ea 05 5f 83 c0 05 c6 01 e9 89 51 01 } //1
		$a_03_2 = {81 3c 39 eb 02 aa aa 0f 84 ?? ?? ?? ?? 8d 04 92 6a 28 53 8d bc c6 f8 00 00 00 } //1
		$a_01_3 = {80 7d 0b bf 76 06 80 7d 0b c4 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}