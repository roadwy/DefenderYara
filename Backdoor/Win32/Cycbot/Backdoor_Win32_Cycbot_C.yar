
rule Backdoor_Win32_Cycbot_C{
	meta:
		description = "Backdoor:Win32/Cycbot.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {84 c0 75 13 68 58 1b 00 00 ff 15 90 01 04 6a 00 ff 15 90 00 } //03 00 
		$a_00_1 = {74 79 70 65 3d 25 73 26 73 79 73 74 65 6d 3d 25 73 26 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 73 } //01 00 
		$a_00_2 = {6e 69 6c 7c 25 73 7c 6e 69 6c } //01 00 
		$a_00_3 = {25 73 3f 74 71 3d 25 73 } //01 00 
		$a_00_4 = {61 74 20 25 64 3a 25 64 20 22 25 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}