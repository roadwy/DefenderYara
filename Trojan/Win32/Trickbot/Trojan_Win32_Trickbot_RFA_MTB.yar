
rule Trojan_Win32_Trickbot_RFA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c9 66 8b 0b 8d 3c 8a 8b 4c 24 90 01 01 8a 15 90 01 04 03 f8 8b 31 33 c9 03 f0 84 d2 74 90 01 01 8b ee 81 ed 90 01 04 8a 94 29 90 01 04 84 d2 74 90 00 } //01 00 
		$a_01_1 = {5a 4d 3f 4a 67 45 6c 62 2a 52 68 61 21 2b 5a } //00 00 
	condition:
		any of ($a_*)
 
}