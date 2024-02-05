
rule Trojan_Win32_Qbot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b fe 46 3b f0 72 f2 85 ff 74 18 8b 4d fc 8b d7 2b d9 66 8b 04 0b 66 89 01 8d 49 02 83 ef 01 75 f1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 45 f0 0f b6 08 3a db 74 40 bb 08 00 00 00 53 3a db 74 4e 03 45 f0 88 08 e9 b8 01 00 00 } //01 00 
		$a_01_1 = {5e f7 f6 66 3b c0 74 c2 } //00 00 
	condition:
		any of ($a_*)
 
}