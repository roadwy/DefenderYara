
rule Backdoor_Win32_Venik_P_bit{
	meta:
		description = "Backdoor:Win32/Venik.P!bit,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00 } //03 00 
		$a_01_1 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00 } //01 00 
		$a_01_2 = {5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //03 00  \System32\svchost.exe -k
		$a_03_3 = {8b 55 08 03 55 fc 8a 02 2c 90 01 01 8b 4d 08 03 4d fc 88 01 eb c9 90 00 } //01 00 
		$a_03_4 = {fe ff ff 53 c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 72 c6 85 90 01 01 fe ff ff 76 c6 85 90 01 01 fe ff ff 69 c6 85 90 01 01 fe ff ff 63 c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 73 c6 85 90 01 01 fe ff ff 5c c6 85 90 01 01 fe ff ff 25 c6 85 90 01 01 fe ff ff 73 88 9d 90 01 01 fe ff ff 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 } //35 a1 
	condition:
		any of ($a_*)
 
}