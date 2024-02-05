
rule Trojan_Win32_Qbot_AW_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 64 42 4e 4f 38 49 37 67 34 47 2e 64 6c 6c } //01 00 
		$a_01_1 = {44 74 6d 71 75 52 6f 44 6b } //01 00 
		$a_01_2 = {45 6b 50 55 48 79 69 79 42 4b } //01 00 
		$a_01_3 = {49 79 47 62 5a 6b 4a 55 } //01 00 
		$a_01_4 = {4e 43 65 71 56 74 75 } //01 00 
		$a_01_5 = {5a 7a 71 64 4e 7a 6b 67 79 68 } //01 00 
		$a_01_6 = {6a 74 57 4b 6d 61 } //01 00 
		$a_01_7 = {64 6c 6d 47 6b 43 } //00 00 
	condition:
		any of ($a_*)
 
}