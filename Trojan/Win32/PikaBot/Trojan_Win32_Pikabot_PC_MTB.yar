
rule Trojan_Win32_Pikabot_PC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {42 0f b6 d2 8a 84 15 90 02 04 01 c1 0f b6 c9 8a 9c 0d 90 02 04 88 9c 15 90 02 04 88 84 0d 90 02 04 02 84 15 90 02 04 0f b6 c0 8a 84 05 90 02 04 32 84 2e 90 02 04 0f b6 c0 66 89 84 75 90 02 04 46 83 fe 90 01 01 75 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 98 66 06 80 5c 2a } //00 00 
	condition:
		any of ($a_*)
 
}