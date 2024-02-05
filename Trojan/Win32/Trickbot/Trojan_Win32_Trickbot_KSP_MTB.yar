
rule Trojan_Win32_Trickbot_KSP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {ff d7 8a 16 6a 00 32 d3 02 d3 88 16 ff d7 46 4d 75 } //02 00 
		$a_02_1 = {8b c6 f7 f3 8b 44 24 90 01 01 8a 04 02 30 01 46 3b 74 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}