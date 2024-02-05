
rule PWS_Win32_Mapdimp_B{
	meta:
		description = "PWS:Win32/Mapdimp.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 19 03 c2 30 18 41 3b ce 72 02 8b cf 42 3b 55 0c 7c ea } //01 00 
		$a_03_1 = {bb 8c 00 00 00 83 c0 f8 33 d2 8b cb 90 02 03 f7 f1 85 c0 7e 90 00 } //01 00 
		$a_03_2 = {83 c0 f8 8b cb f7 f1 01 5d 90 01 01 83 c4 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}