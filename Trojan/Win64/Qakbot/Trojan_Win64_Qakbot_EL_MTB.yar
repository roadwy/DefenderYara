
rule Trojan_Win64_Qakbot_EL_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 44 01 10 8b 8c 24 98 00 00 00 } //01 00 
		$a_01_1 = {33 c8 8b c1 } //01 00 
		$a_01_2 = {48 63 4c 24 4c 48 8b 54 24 78 } //01 00 
		$a_01_3 = {88 04 0a e9 } //00 00 
	condition:
		any of ($a_*)
 
}