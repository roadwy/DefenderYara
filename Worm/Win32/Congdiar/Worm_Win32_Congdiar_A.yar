
rule Worm_Win32_Congdiar_A{
	meta:
		description = "Worm:Win32/Congdiar.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 46 fe 83 f8 04 77 2a ff 24 85 90 01 04 ba 90 01 04 eb 21 ba 90 01 04 eb 1a 90 00 } //1
		$a_00_1 = {56 00 69 00 72 00 75 00 73 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 21 00 21 00 21 00 } //1 Virus found !!!
		$a_00_2 = {3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 :\Autorun.inf
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}