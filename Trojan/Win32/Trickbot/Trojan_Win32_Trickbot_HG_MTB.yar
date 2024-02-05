
rule Trojan_Win32_Trickbot_HG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 90 02 09 3b 78 14 90 02 11 83 c0 04 8b 00 eb 90 01 01 83 c0 04 8a 90 01 02 30 90 01 01 8b 90 02 09 3b 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}