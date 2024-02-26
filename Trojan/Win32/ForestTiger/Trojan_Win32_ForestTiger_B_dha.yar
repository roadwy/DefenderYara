
rule Trojan_Win32_ForestTiger_B_dha{
	meta:
		description = "Trojan:Win32/ForestTiger.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 64 00 "
		
	strings :
		$a_01_0 = {34 00 38 00 30 00 30 00 2d 00 38 00 34 00 44 00 43 00 2d 00 30 00 36 00 33 00 41 00 36 00 41 00 34 00 31 00 43 00 35 00 43 00 } //64 00  4800-84DC-063A6A41C5C
		$a_01_1 = {75 54 59 4e 6b 66 4b 78 48 69 5a 72 78 33 4b 4a } //00 00  uTYNkfKxHiZrx3KJ
	condition:
		any of ($a_*)
 
}