
rule PWS_Win32_Cupsop_A{
	meta:
		description = "PWS:Win32/Cupsop.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 6d 75 0a 80 7b 05 02 0f 84 90 01 02 00 00 3c c9 75 0a 80 7b 05 00 0f 84 90 01 02 00 00 3c 64 0f 85 90 01 02 00 00 80 7b 05 00 0f 85 90 00 } //1
		$a_01_1 = {75 5e 80 7e 05 02 75 58 8a 56 0c 8d 46 0c 84 d2 74 4e 33 c9 80 fa 2f 74 07 41 80 3c 08 2f 75 f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}