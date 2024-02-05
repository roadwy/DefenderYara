
rule Trojan_Win32_Qbot_RFA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 8b 15 90 01 04 31 02 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RFA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 6f 66 59 6b 75 79 } //EofYkuy  01 00 
		$a_80_1 = {50 65 69 64 48 67 6a 57 69 } //PeidHgjWi  01 00 
		$a_80_2 = {55 79 4b 58 52 54 54 4d 65 53 } //UyKXRTTMeS  01 00 
		$a_80_3 = {4a 6c 4d 79 63 71 43 } //JlMycqC  01 00 
		$a_80_4 = {66 47 46 4f 44 5a 7a 48 50 } //fGFODZzHP  01 00 
		$a_80_5 = {69 55 67 62 69 6f 43 45 } //iUgbioCE  01 00 
		$a_80_6 = {78 56 6a 72 41 77 53 73 } //xVjrAwSs  00 00 
	condition:
		any of ($a_*)
 
}