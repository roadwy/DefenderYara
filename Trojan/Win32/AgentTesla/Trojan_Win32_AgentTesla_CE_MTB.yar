
rule Trojan_Win32_AgentTesla_CE_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 0f b6 c0 8a 84 05 90 02 04 30 04 19 41 89 4d fc 3b 4d 08 72 9b 90 00 } //01 00 
		$a_03_1 = {33 d2 88 8c 0d 90 02 04 8b c1 f7 75 90 01 01 8a 04 3a 88 84 0d 90 02 04 41 81 f9 00 01 00 00 7c df 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}