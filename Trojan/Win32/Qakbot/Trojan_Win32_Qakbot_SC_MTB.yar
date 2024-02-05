
rule Trojan_Win32_Qakbot_SC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 96 4c 01 00 00 8b 46 90 01 01 41 09 90 01 05 8b 46 90 01 01 69 80 90 01 08 3b c8 76 90 00 } //01 00 
		$a_03_1 = {8b 81 ec 00 00 00 31 86 90 01 04 ff 89 90 01 04 8b 86 90 01 04 2d 90 01 04 89 86 90 01 04 ff 77 90 01 01 8b 47 90 01 01 03 46 90 00 } //01 00 
		$a_00_2 = {44 51 46 69 46 61 30 79 } //00 00 
	condition:
		any of ($a_*)
 
}