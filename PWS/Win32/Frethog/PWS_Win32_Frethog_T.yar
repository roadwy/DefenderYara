
rule PWS_Win32_Frethog_T{
	meta:
		description = "PWS:Win32/Frethog.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 6d 3d 25 64 00 46 6f 72 74 68 67 6f 65 72 } //1
		$a_01_1 = {76 16 8b 45 08 8d 14 06 8b 5d 10 8a 04 0a 3a 04 19 75 05 41 3b cf 72 f0 3b cf 74 0d 46 3b 75 0c } //1
		$a_01_2 = {c7 45 f4 20 57 6e 64 c7 45 f8 43 6c 61 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}