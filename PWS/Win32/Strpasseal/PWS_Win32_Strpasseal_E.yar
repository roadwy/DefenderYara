
rule PWS_Win32_Strpasseal_E{
	meta:
		description = "PWS:Win32/Strpasseal.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 3b 26 75 4f 8b 03 3d 26 6c 74 3b 75 06 c6 04 37 3c eb 0b 3d 26 67 74 3b } //1
		$a_01_1 = {80 30 19 40 80 38 00 75 f7 } //1
		$a_03_2 = {bb 00 10 40 00 2b fb 8d 87 ?? ?? ?? ?? 89 45 ?? 56 68 00 00 00 08 6a 40 8d 45 } //1
		$a_01_3 = {be f3 4b 70 ed 33 db 68 6e 10 cf 9f 89 75 c8 c7 45 cc 8c f8 6f 8b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}