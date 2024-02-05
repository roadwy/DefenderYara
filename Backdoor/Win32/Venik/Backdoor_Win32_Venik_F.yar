
rule Backdoor_Win32_Venik_F{
	meta:
		description = "Backdoor:Win32/Venik.F,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 ea 90 01 01 80 f2 90 01 01 88 14 01 41 3b 90 02 04 7c 90 00 } //01 00 
		$a_03_1 = {fe ff ff 53 c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 72 c6 85 90 01 01 fe ff ff 76 c6 85 90 01 01 fe ff ff 69 c6 85 90 01 01 fe ff ff 63 c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 73 c6 85 90 01 01 fe ff ff 5c c6 85 90 01 01 fe ff ff 25 c6 85 90 01 01 fe ff ff 73 88 9d 90 01 01 fe ff ff 90 00 } //01 00 
		$a_01_2 = {6a 00 81 c2 90 fe ff ff 51 81 c3 70 01 00 00 52 53 56 ff 15 } //03 00 
		$a_01_3 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00 } //03 00 
		$a_01_4 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00 } //00 00 
		$a_00_5 = {7e 15 00 00 } //7e 31 
	condition:
		any of ($a_*)
 
}