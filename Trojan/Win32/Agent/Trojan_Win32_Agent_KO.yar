
rule Trojan_Win32_Agent_KO{
	meta:
		description = "Trojan:Win32/Agent.KO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 76 50 6a 00 ff 15 90 01 04 85 c0 74 90 01 01 89 90 01 01 fc fc 56 8b 4e 54 8b 75 08 8b 90 01 01 fc 33 c0 f3 a4 5e 90 00 } //01 00 
		$a_03_1 = {51 b9 b6 dc 0e 00 81 c1 1c 02 00 00 8b 45 d4 d1 c0 c1 c8 90 01 01 85 c0 c1 c0 90 01 01 50 8f 45 d4 90 00 } //01 00 
		$a_03_2 = {68 00 00 cf 00 68 90 01 04 68 90 01 04 6a 00 ff 15 90 01 04 89 45 cc 6a 00 ff 75 cc e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}