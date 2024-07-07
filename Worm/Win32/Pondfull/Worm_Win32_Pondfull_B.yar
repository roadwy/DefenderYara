
rule Worm_Win32_Pondfull_B{
	meta:
		description = "Worm:Win32/Pondfull.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_13_0 = {c9 31 04 0b 05 90 01 04 83 c1 04 81 f9 90 01 03 00 75 ed eb 05 e8 de ff ff ff 90 00 01 } //1
		$a_5e_1 = {d6 00 00 80 7c 00 00 dd 77 00 00 ab 71 00 00 41 7e 00 00 } //11520
	condition:
		((#a_13_0  & 1)*1+(#a_5e_1  & 1)*11520) >=2
 
}