
rule Trojan_Win32_Qakbot_PR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 bb 04 00 00 00 53 90 13 5e f7 f6 0f b6 44 15 90 01 01 66 3b d2 90 13 33 c8 8b 45 90 01 01 88 4c 05 90 01 01 e9 90 01 04 e9 90 01 04 8b 40 90 01 01 8b 4d 90 01 01 8d 44 01 90 01 01 66 3b ed 90 13 89 45 90 01 01 bb d2 04 00 00 53 66 3b ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}