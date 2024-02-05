
rule Backdoor_Win32_Yonsole_A{
	meta:
		description = "Backdoor:Win32/Yonsole.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d 05 08 00 00 77 90 01 01 74 90 01 01 8b c8 83 e9 02 74 90 01 01 81 e9 02 08 00 00 90 00 } //01 00 
		$a_01_1 = {75 11 8b 45 10 8b 4d 1c 03 c1 89 84 24 } //01 00 
		$a_03_2 = {7e 1f 8b 4c 24 04 8a 14 31 80 c2 90 01 01 88 14 31 8b 4c 24 04 8a 14 31 80 f2 90 01 01 88 14 31 46 3b f0 7c e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}