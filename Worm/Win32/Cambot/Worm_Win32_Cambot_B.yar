
rule Worm_Win32_Cambot_B{
	meta:
		description = "Worm:Win32/Cambot.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 73 5f 62 6f 74 } //01 00 
		$a_01_1 = {74 6d 72 47 72 61 62 62 65 72 } //01 00 
		$a_01_2 = {2f 00 63 00 6d 00 64 00 2e 00 70 00 68 00 70 00 3f 00 6b 00 65 00 79 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}