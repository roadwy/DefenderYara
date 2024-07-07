
rule Worm_Win32_Neeris_BK{
	meta:
		description = "Worm:Win32/Neeris.BK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 72 f1 83 3d 90 01 04 00 74 90 02 06 f6 d0 88 04 37 56 47 90 00 } //1
		$a_01_1 = {6e 6f 20 6b 69 63 6b 20 6d 65 20 6e 69 67 67 61 20 25 73 } //1 no kick me nigga %s
		$a_01_2 = {70 31 69 63 6b 61 2e 73 74 70 } //1 p1icka.stp
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}