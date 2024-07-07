
rule Worm_Win32_Bainoc_B{
	meta:
		description = "Worm:Win32/Bainoc.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 45 f8 04 62 e8 90 01 04 88 45 f7 8d 45 d8 8a 55 f7 e8 90 01 04 8d 45 d8 ba 90 01 04 e8 90 01 04 8b 45 d8 e8 90 01 04 50 e8 90 01 04 8b d8 80 fb 02 74 09 80 fb 03 0f 85 90 00 } //1
		$a_01_1 = {49 6e 66 65 63 74 20 50 65 6e 44 72 69 76 65 72 3a } //1 Infect PenDriver:
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}