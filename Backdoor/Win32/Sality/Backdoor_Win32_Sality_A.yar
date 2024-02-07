
rule Backdoor_Win32_Sality_A{
	meta:
		description = "Backdoor:Win32/Sality.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f8 02 7e 4b 8a 85 } //03 00 
		$a_03_1 = {25 ff 00 00 00 8b 8d 90 01 03 ff 81 e1 ff 00 00 00 0f af c1 05 38 04 00 00 66 a3 90 00 } //02 00 
		$a_01_2 = {8b 55 08 66 c7 42 06 1e 00 8b 45 08 c7 40 08 3d 00 00 00 6a 3d 68 } //02 00 
		$a_01_3 = {26 25 78 3d 25 64 26 69 64 3d 25 64 } //01 00  &%x=%d&id=%d
		$a_01_4 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a } //00 00  %s:*:Enabled:
	condition:
		any of ($a_*)
 
}