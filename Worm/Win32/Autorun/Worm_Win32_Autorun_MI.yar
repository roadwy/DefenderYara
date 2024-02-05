
rule Worm_Win32_Autorun_MI{
	meta:
		description = "Worm:Win32/Autorun.MI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 5c 61 75 74 89 04 24 8d bd 90 01 02 ff ff bb 6f 72 75 6e 8b 4c 95 90 01 01 89 4c 24 90 01 01 e8 90 00 } //01 00 
		$a_01_1 = {44 3a 00 45 3a 00 46 3a 00 } //00 00 
	condition:
		any of ($a_*)
 
}