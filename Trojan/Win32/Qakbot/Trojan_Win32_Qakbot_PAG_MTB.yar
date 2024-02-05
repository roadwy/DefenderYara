
rule Trojan_Win32_Qakbot_PAG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 bb 04 00 00 00 90 13 53 5e 3a ed 90 13 f7 f6 0f b6 44 15 90 01 01 66 3b d2 90 13 33 c8 8b 45 90 01 01 90 13 88 4c 05 90 01 01 90 13 8b 45 90 01 01 eb 00 40 89 45 90 01 01 e9 90 00 } //01 00 
		$a_01_1 = {70 72 69 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}