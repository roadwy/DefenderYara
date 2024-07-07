
rule Worm_Win32_Otwycal_gen_A{
	meta:
		description = "Worm:Win32/Otwycal.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 fe ac 26 00 00 7f 23 83 f8 63 7f 1e 80 f9 2a 75 08 } //1
		$a_03_1 = {2e c6 84 24 90 01 02 00 00 65 c6 84 24 90 01 02 00 00 78 c6 84 24 90 01 02 00 00 74 88 84 24 90 01 02 00 00 c6 84 24 90 01 02 00 00 64 c6 84 24 90 01 02 00 00 6f c6 84 24 90 01 02 00 00 77 c6 84 24 90 01 02 00 00 73 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}