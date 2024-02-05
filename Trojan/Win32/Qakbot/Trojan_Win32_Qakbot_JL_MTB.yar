
rule Trojan_Win32_Qakbot_JL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ec 51 c7 45 90 01 01 90 01 04 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 c7 45 90 1b 00 90 1b 01 90 00 } //01 00 
		$a_02_1 = {03 01 8b 55 90 01 01 89 02 8b 45 90 1b 00 8b 08 81 e9 90 01 04 8b 55 90 1b 00 89 0a 90 0a 25 00 8d 84 02 90 1b 02 8b 4d 90 1b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}