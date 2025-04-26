
rule PWS_Win32_Mapdimp_B{
	meta:
		description = "PWS:Win32/Mapdimp.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 19 03 c2 30 18 41 3b ce 72 02 8b cf 42 3b 55 0c 7c ea } //1
		$a_03_1 = {bb 8c 00 00 00 83 c0 f8 33 d2 8b cb [0-03] f7 f1 85 c0 7e } //1
		$a_03_2 = {83 c0 f8 8b cb f7 f1 01 5d ?? 83 c4 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}