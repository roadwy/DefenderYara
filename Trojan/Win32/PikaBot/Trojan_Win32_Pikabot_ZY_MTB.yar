
rule Trojan_Win32_Pikabot_ZY_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.ZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 41 eb 79 b9 90 01 04 81 c1 90 01 04 eb 45 03 c3 89 45 f0 eb 30 b9 3c 7f 00 00 81 c1 c4 00 00 00 eb 1c 69 45 f0 6d 4e c6 41 bb 39 30 00 00 eb de 48 89 45 ec e9 90 00 } //01 00 
		$a_01_1 = {43 72 61 73 68 } //00 00  Crash
	condition:
		any of ($a_*)
 
}