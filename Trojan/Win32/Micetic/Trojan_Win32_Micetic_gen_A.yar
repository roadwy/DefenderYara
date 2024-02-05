
rule Trojan_Win32_Micetic_gen_A{
	meta:
		description = "Trojan:Win32/Micetic.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 40 83 fa 90 01 01 7c f6 90 09 03 00 80 00 90 00 } //01 00 
		$a_01_1 = {2d 72 00 25 73 20 2d 73 00 } //01 00 
		$a_01_2 = {6a 8f 95 86 93 8f 86 95 64 90 8f 8f 86 84 95 62 } //01 00 
		$a_01_3 = {80 3b e9 75 04 33 c0 eb 6a e8 } //00 00 
	condition:
		any of ($a_*)
 
}