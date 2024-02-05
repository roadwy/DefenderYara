
rule Trojan_Win32_Qakbot_PL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 70 64 74 } //01 00 
		$a_01_1 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //01 00 
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}