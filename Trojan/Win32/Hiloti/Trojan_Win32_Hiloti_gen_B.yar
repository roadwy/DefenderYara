
rule Trojan_Win32_Hiloti_gen_B{
	meta:
		description = "Trojan:Win32/Hiloti.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 40 10 3d 00 00 03 00 0f 8f 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {8b 42 18 2d 00 00 00 01 } //01 00 
		$a_03_2 = {c9 83 04 24 90 01 01 c2 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}