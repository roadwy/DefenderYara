
rule Trojan_Win32_Acbot_B{
	meta:
		description = "Trojan:Win32/Acbot.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {23 23 53 54 4f 50 4d 59 53 50 41 43 45 23 23 } //01 00 
		$a_00_1 = {4d 61 6c 65 6b 61 6c } //01 00 
		$a_00_2 = {73 74 6f 70 68 6f 6f 6b } //01 00 
		$a_01_3 = {50 52 4f 43 4d 4f 4e 5f 57 49 4e 44 4f 57 5f 43 4c 41 53 53 } //01 00 
		$a_00_4 = {53 6d 61 72 74 53 6e 69 66 66 } //00 00 
		$a_00_5 = {80 10 00 00 } //4f 96 
	condition:
		any of ($a_*)
 
}