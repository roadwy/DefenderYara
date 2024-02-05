
rule Trojan_Win32_Qakbot_PH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 66 3b c0 74 90 01 01 80 45 90 01 01 46 e9 90 01 04 c6 45 90 01 01 1f eb 90 01 01 c6 45 90 01 01 40 80 45 90 01 01 12 3a f6 74 90 01 01 c6 45 90 01 01 4c 80 45 90 01 01 20 66 3b e4 74 90 01 01 c6 45 90 01 01 24 80 45 90 01 01 20 3a f6 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}