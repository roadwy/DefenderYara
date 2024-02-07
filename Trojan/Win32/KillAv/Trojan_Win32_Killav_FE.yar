
rule Trojan_Win32_Killav_FE{
	meta:
		description = "Trojan:Win32/Killav.FE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 00 45 00 4d 00 50 00 5c 00 41 00 56 00 2d 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 2e 00 62 00 61 00 74 00 00 00 } //01 00 
		$a_01_1 = {6e 65 74 20 73 74 6f 70 20 93 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //01 00 
		$a_00_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 } //01 00  netsh firewall set opmode mode=disable
		$a_00_3 = {74 73 6b 69 6c 6c 20 2f 41 20 61 76 2a } //00 00  tskill /A av*
	condition:
		any of ($a_*)
 
}