
rule Trojan_Win32_Qbot_CP_MTB{
	meta:
		description = "Trojan:Win32/Qbot.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 38 8b 5c 24 34 83 c5 56 8b 7c 24 34 83 c3 36 8b 74 24 28 83 c7 5b 8b 54 24 38 83 ee 48 8b 4c 24 24 83 c2 34 8b 44 24 30 } //01 00 
		$a_03_1 = {8b 7c 24 48 83 eb 3a 8b 74 24 54 81 c7 90 01 04 8b 54 24 60 83 c6 06 8b 4c 24 44 83 ea 34 89 84 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}