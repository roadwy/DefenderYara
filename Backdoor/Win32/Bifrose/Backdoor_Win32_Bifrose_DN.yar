
rule Backdoor_Win32_Bifrose_DN{
	meta:
		description = "Backdoor:Win32/Bifrose.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 a3 90 01 02 40 00 8b 0d 90 01 02 40 00 3b 0d 90 01 02 40 00 7e 0c 8b 15 90 01 02 40 00 89 15 90 01 02 40 00 90 00 } //01 00 
		$a_01_1 = {6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d f8 00 } //01 00 
		$a_03_2 = {68 94 02 00 00 8b 0d 90 01 02 40 00 51 68 94 02 00 00 8b 95 90 01 04 52 8b 45 90 01 01 03 05 90 01 02 40 00 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}