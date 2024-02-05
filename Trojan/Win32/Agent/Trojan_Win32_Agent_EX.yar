
rule Trojan_Win32_Agent_EX{
	meta:
		description = "Trojan:Win32/Agent.EX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 6d 70 7a 2e 69 6e 69 } //01 00 
		$a_03_1 = {80 f9 3a 75 47 c6 84 05 90 01 04 00 8a 8c 05 90 01 02 ff ff 40 80 f9 2f c7 45 90 01 01 01 00 00 00 75 1c 8a 8c 05 90 01 02 ff ff 40 80 f9 2f 75 2d 40 90 00 } //01 00 
		$a_01_2 = {8a 01 8a d0 3a 06 75 1c 84 d2 74 14 8a 41 01 8a d0 3a 46 01 75 0e 83 c1 02 83 c6 02 } //00 00 
	condition:
		any of ($a_*)
 
}