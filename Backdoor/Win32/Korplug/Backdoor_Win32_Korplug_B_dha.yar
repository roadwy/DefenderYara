
rule Backdoor_Win32_Korplug_B_dha{
	meta:
		description = "Backdoor:Win32/Korplug.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {33 c0 f2 ae f7 d1 49 51 68 90 01 04 e8 90 01 04 83 c4 08 33 c0 b9 19 00 00 00 8d 7c 90 01 02 50 50 50 50 f3 ab 68 90 01 04 c7 44 90 01 02 00 00 00 00 ff 15 90 00 } //01 00 
		$a_00_1 = {63 6d 64 20 2f 63 20 22 70 69 6e 67 20 31 26 64 65 6c 20 2f 51 20 22 25 73 2a 2e 2a } //01 00  cmd /c "ping 1&del /Q "%s*.*
		$a_00_2 = {73 6c 69 64 65 73 2e 69 6e 66 } //00 00  slides.inf
		$a_00_3 = {5d 04 00 00 } //f4 63 
	condition:
		any of ($a_*)
 
}