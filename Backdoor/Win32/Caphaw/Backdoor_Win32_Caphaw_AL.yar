
rule Backdoor_Win32_Caphaw_AL{
	meta:
		description = "Backdoor:Win32/Caphaw.AL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 04 8b 41 3c 0f b7 54 08 14 03 c1 0f b7 48 06 53 03 d0 56 8d 34 89 8d 44 f2 f0 33 d2 85 c9 76 } //02 00 
		$a_01_1 = {8d 0c 89 8d 44 ca f0 c7 04 24 00 00 00 00 89 04 24 8b 04 24 59 c3 } //02 00 
		$a_01_2 = {83 c0 f8 d1 e8 85 c0 8d 72 08 76 } //02 00 
		$a_01_3 = {8b 42 38 8b 0e 8d 54 01 ff 48 f7 d0 } //00 00 
	condition:
		any of ($a_*)
 
}