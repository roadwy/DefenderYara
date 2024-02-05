
rule Trojan_Win32_Qbot_PBI_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 45 f0 0f b6 08 eb 90 01 01 0f b6 44 10 90 01 01 33 c8 eb 3b bb 03 00 00 00 83 c3 05 eb 90 01 01 8b 45 f0 33 d2 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}