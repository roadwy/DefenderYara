
rule Trojan_Win32_Qakbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6f 33 6a 43 6e 53 61 71 } //02 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //02 00 
		$a_01_2 = {45 4d 62 76 46 5a 4d 69 64 64 } //02 00 
		$a_01_3 = {45 51 34 65 50 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 68 79 38 2e 64 6c 6c } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_2 = {41 64 64 46 6f 6e 74 52 65 73 6f 75 72 63 65 57 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 49 42 50 61 74 74 65 72 6e 42 72 75 73 68 50 74 } //01 00 
		$a_01_4 = {47 65 74 43 68 61 72 41 42 43 57 69 64 74 68 73 41 } //01 00 
		$a_01_5 = {47 65 74 47 6c 79 70 68 4f 75 74 6c 69 6e 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}