
rule Trojan_Win32_Qbot_RD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 04 24 8b 4c 24 90 01 01 8a 14 01 c7 44 24 14 28 64 af 17 8b 74 24 90 01 01 88 14 06 83 c0 01 8b 7c 24 90 01 01 39 f8 89 04 24 74 90 01 01 eb 90 00 } //01 00 
		$a_02_1 = {88 04 0e 8b 4c 24 90 01 01 81 c1 fc 6f 4d bd 66 8b 7c 24 90 01 01 66 23 7c 24 90 01 01 66 89 7c 24 90 01 01 03 4c 24 90 01 01 89 4c 24 90 01 01 66 8b 7c 24 90 01 01 66 81 c7 dc c0 66 89 7c 24 90 01 01 8b 5c 24 90 01 01 39 d9 0f 84 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}