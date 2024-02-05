
rule Trojan_Win32_Qakbot_EG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {66 7a 31 43 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 54 4c 58 69 77 4b 61 43 } //01 00 
		$a_01_3 = {44 4b 61 62 71 4a 78 71 55 } //01 00 
		$a_01_4 = {48 70 74 50 6d 35 57 54 51 6f 32 } //01 00 
		$a_01_5 = {4b 39 38 42 4f 71 4a 58 36 6a 68 } //00 00 
	condition:
		any of ($a_*)
 
}