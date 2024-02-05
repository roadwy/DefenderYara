
rule Backdoor_Win32_Wakbot_B{
	meta:
		description = "Backdoor:Win32/Wakbot.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {f7 b1 04 01 00 00 8a 04 3e 8a 14 0a 3a c2 74 09 84 c0 74 05 32 c2 88 04 90 04 01 01 3e 90 00 } //01 00 
		$a_01_1 = {8b c2 8b cf 23 c3 83 ef 06 d3 f8 c1 ea 06 85 c0 75 1f } //01 00 
		$a_00_2 = {33 ed 83 c0 04 ba 00 00 fc 00 bf 12 00 00 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 1c 
	condition:
		any of ($a_*)
 
}