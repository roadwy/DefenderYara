
rule Trojan_Win32_Qakbot_SAS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 03 45 90 01 01 0f b6 08 3a f6 74 90 01 01 8b 45 90 01 01 0f b6 44 10 90 01 01 33 c8 66 90 01 01 74 90 00 } //01 00 
		$a_03_1 = {8b 45 ec 03 45 90 01 01 88 08 e9 90 01 04 e9 90 01 04 53 5e f7 f6 66 90 01 02 74 90 00 } //01 00 
		$a_00_2 = {57 69 6e 64 } //00 00  Wind
	condition:
		any of ($a_*)
 
}