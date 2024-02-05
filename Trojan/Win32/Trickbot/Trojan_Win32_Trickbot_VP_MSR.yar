
rule Trojan_Win32_Trickbot_VP_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.VP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 72 6d 53 70 6c 69 6e 65 73 } //01 00 
		$a_81_1 = {6d 6f 64 53 70 6c 69 6e 65 73 } //01 00 
		$a_81_2 = {66 72 6d 43 6f 70 79 72 69 67 68 74 } //01 00 
		$a_81_3 = {66 72 6d 49 73 74 72 75 7a 69 6f 6e 69 } //01 00 
		$a_81_4 = {53 70 6c 69 6e 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}