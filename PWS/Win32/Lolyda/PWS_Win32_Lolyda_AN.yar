
rule PWS_Win32_Lolyda_AN{
	meta:
		description = "PWS:Win32/Lolyda.AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 33 55 04 90 01 01 34 90 01 01 2c 90 01 01 47 88 06 46 ff 15 90 01 04 3b f8 7c e8 90 00 } //1
		$a_03_1 = {2b de c6 06 e9 90 02 02 8d 83 90 01 04 90 02 01 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02 90 00 } //2
		$a_03_2 = {68 d0 07 00 00 ff 15 90 01 04 a1 90 01 04 85 c0 74 ec a0 90 01 04 84 c0 74 e3 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}