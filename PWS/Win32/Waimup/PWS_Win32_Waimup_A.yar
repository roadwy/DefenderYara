
rule PWS_Win32_Waimup_A{
	meta:
		description = "PWS:Win32/Waimup.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 2c da 92 00 8b 00 83 c0 20 8b 00 05 04 05 00 00 8b 00 b9 10 27 00 00 33 d2 f7 f1 } //1
		$a_03_1 = {6a 02 6a 00 68 ef fe ff ff 53 e8 90 01 04 8d 45 90 01 01 e8 90 01 04 6a 00 68 fc cd 40 00 68 11 01 00 00 a1 90 01 04 50 53 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}