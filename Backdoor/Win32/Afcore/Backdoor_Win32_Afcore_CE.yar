
rule Backdoor_Win32_Afcore_CE{
	meta:
		description = "Backdoor:Win32/Afcore.CE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 59 89 45 90 01 01 59 c1 e8 08 33 c9 8b d1 83 e2 03 02 44 15 90 01 01 30 81 90 01 04 41 81 f9 90 01 03 00 72 e8 90 00 } //01 00 
		$a_01_1 = {75 08 8b f1 33 74 24 0c 03 c6 03 c2 41 83 c2 06 3b 4c 24 08 72 e8 } //01 00 
		$a_03_2 = {ff d0 68 00 80 00 00 6a 00 ff 35 90 01 04 ff 55 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}