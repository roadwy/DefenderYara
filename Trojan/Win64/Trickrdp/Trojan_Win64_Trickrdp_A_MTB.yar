
rule Trojan_Win64_Trickrdp_A_MTB{
	meta:
		description = "Trojan:Win64/Trickrdp.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {72 64 70 73 63 61 6e 2e 64 6c 6c } //rdpscan.dll  01 00 
		$a_80_1 = {42 6f 74 49 44 } //BotID  01 00 
		$a_80_2 = {74 72 79 62 72 75 74 65 } //trybrute  01 00 
		$a_80_3 = {72 64 70 2f 6e 61 6d 65 73 } //rdp/names  01 00 
		$a_80_4 = {72 64 70 2f 64 69 63 74 } //rdp/dict  01 00 
		$a_80_5 = {72 64 70 2f 6f 76 65 72 } //rdp/over  01 00 
		$a_80_6 = {72 64 70 2f 66 72 65 71 } //rdp/freq  01 00 
		$a_80_7 = {72 64 70 2f 64 6f 6d 61 69 6e 73 } //rdp/domains  00 00 
	condition:
		any of ($a_*)
 
}