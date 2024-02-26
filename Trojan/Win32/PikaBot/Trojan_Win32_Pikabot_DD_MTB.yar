
rule Trojan_Win32_Pikabot_DD_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 0f b6 4c 05 90 } //01 00 
		$a_01_1 = {f7 f6 0f b6 44 15 8c } //01 00 
		$a_01_2 = {33 c8 8b 45 ec } //01 00 
		$a_01_3 = {88 4c 05 90 } //00 00 
	condition:
		any of ($a_*)
 
}