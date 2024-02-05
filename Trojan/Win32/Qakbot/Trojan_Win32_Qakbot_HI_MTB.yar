
rule Trojan_Win32_Qakbot_HI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 15 a0 33 c8 66 3b ff 74 90 01 01 8b 45 90 01 01 8b 40 90 01 01 3a db 74 90 01 01 8b 45 90 01 01 0f b6 4c 05 90 01 01 66 3b f6 74 90 01 01 8b 4d 90 01 01 8d 44 01 90 01 01 3a c9 74 90 00 } //01 00 
		$a_03_1 = {bb 04 00 00 00 53 66 3b c0 74 90 01 01 8b 45 90 01 01 33 d2 66 3b ff 74 90 01 01 89 45 90 01 01 bb 90 01 04 eb 90 01 01 8b 45 90 01 01 88 4c 05 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}