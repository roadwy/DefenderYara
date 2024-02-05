
rule Trojan_Win32_Qakbot_FO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_2 = {6a 76 6d 6b 76 62 31 31 34 61 64 2e 64 6c 6c } //01 00 
		$a_01_3 = {52 71 43 34 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}