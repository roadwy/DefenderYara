
rule PWS_Win32_Wowsteal_Z{
	meta:
		description = "PWS:Win32/Wowsteal.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 de fd ff ff 53 e8 90 01 04 8d 45 80 e8 90 01 04 6a 00 68 90 01 04 68 22 02 00 00 a1 90 01 04 50 53 e8 90 00 } //2
		$a_01_1 = {8a 18 80 c3 23 80 f3 17 80 eb 23 88 1a 42 40 49 75 ee } //1
		$a_01_2 = {8a 0c 10 80 c1 88 80 f1 77 80 e9 88 8b 1d 08 a1 40 00 88 0c 13 42 81 fa 22 02 00 00 75 e2 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}