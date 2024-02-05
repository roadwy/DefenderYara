
rule Backdoor_Win32_Flibot{
	meta:
		description = "Backdoor:Win32/Flibot,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 00 49 00 4e 00 47 00 } //01 00 
		$a_00_1 = {50 00 4f 00 4e 00 47 00 } //01 00 
		$a_00_2 = {4a 00 4f 00 49 00 4e 00 } //05 00 
		$a_00_3 = {46 00 4c 00 56 00 50 00 40 00 4a 00 4b 00 49 00 } //0a 00 
		$a_03_4 = {66 33 45 d0 0f bf d0 52 ff 15 90 01 04 8b d0 8d 4d c8 ff 15 90 01 04 50 ff 15 90 01 04 8b d0 8d 4d d4 ff 15 90 00 } //0a 00 
		$a_03_5 = {66 33 45 d0 0f bf c0 50 e8 90 01 04 8b d0 8d 4d c8 e8 90 01 04 50 e8 90 01 04 8b d0 8d 4d d4 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}