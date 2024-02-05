
rule Trojan_Win32_Qakbot_AI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 66 30 61 62 32 37 31 37 61 66 39 62 66 65 30 } //01 00 
		$a_01_1 = {33 61 36 66 37 64 63 30 36 62 37 63 31 62 66 31 } //01 00 
		$a_01_2 = {35 33 63 64 37 65 37 34 36 39 63 33 33 32 63 30 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AI_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {69 66 3b e4 74 90 01 01 c6 45 90 01 01 72 66 3b db 74 90 01 01 c6 45 90 01 01 65 66 3b ed 74 90 01 01 c6 45 90 01 01 53 66 3b f6 74 90 01 01 c6 45 90 01 01 76 eb 90 01 01 c6 45 90 01 01 72 66 3b d2 74 90 01 01 c6 45 90 01 01 73 3a e4 74 90 01 01 c6 45 90 01 01 65 3a d2 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}