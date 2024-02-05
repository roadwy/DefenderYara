
rule Trojan_Win32_Qakbot_GPA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8b c1 83 e0 7f 8a 04 30 32 04 39 0f b6 c0 66 89 04 5a 43 41 3b 5d fc 72 } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}