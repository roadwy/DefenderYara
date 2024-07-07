
rule PWS_Win32_Mapdimp_A{
	meta:
		description = "PWS:Win32/Mapdimp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 6a fc ff 75 dc ff 15 90 01 04 6a 00 8d 45 d8 50 6a 04 8d 45 f0 50 ff 75 dc ff 15 90 01 04 81 7d f0 02 00 00 08 90 00 } //1
		$a_01_1 = {8a 00 32 01 8b 4d 08 03 4d f8 88 01 8b 45 fc 40 89 45 fc 8b 45 10 03 45 14 39 45 fc 72 08 8b 45 10 89 45 f4 eb 06 } //1
		$a_01_2 = {c7 45 f0 64 26 74 3d c7 45 f4 25 73 26 71 c7 45 f8 3d 25 73 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}