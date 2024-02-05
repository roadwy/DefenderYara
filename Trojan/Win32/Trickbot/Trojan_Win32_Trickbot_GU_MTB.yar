
rule Trojan_Win32_Trickbot_GU_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 8b 74 24 90 01 01 b8 90 01 04 f7 e1 8b c1 2b c2 90 02 0a 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}