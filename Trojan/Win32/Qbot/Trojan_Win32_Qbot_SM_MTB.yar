
rule Trojan_Win32_Qbot_SM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 } //01 00 
		$a_01_1 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3 } //01 00 
		$a_03_2 = {33 d9 c7 05 90 01 04 00 00 00 00 01 1d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5b 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}