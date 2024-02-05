
rule Trojan_Win32_Qbot_PAI_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a d6 0f b6 87 90 01 04 6b c0 90 01 01 d2 ea 22 d0 8b c6 46 85 c0 74 0f 8b 4f 1c 8a 04 0b 02 c0 0a c2 88 04 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}