
rule Trojan_Win32_Trickbot_GK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d0 81 e2 90 02 04 79 90 01 01 4a 83 ca e0 42 8a 14 3a 30 14 08 40 3b c6 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}