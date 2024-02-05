
rule Backdoor_Win32_Dridex{
	meta:
		description = "Backdoor:Win32/Dridex,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 65 72 00 75 00 33 32 2e 64 00 6e 65 6c 00 6c 6c 00 65 74 57 00 69 6e 64 6f 00 47 00 77 4c 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Dridex_2{
	meta:
		description = "Backdoor:Win32/Dridex,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ec e7 57 06 c7 45 ff c5 27 6e fb c7 45 03 c9 3c 83 63 c7 45 07 a9 74 0b cd e8 6f 23 03 00 4c 89 75 ef 41 8b fe 48 8d 4d d7 e8 4b 2d 03 00 48 8d } //00 00 
		$a_00_1 = {7e 15 00 00 05 7f f2 cc e2 49 } //5f c9 
	condition:
		any of ($a_*)
 
}