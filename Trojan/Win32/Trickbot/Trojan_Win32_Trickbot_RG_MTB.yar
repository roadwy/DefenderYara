
rule Trojan_Win32_Trickbot_RG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c9 39 4c 90 01 02 74 90 01 01 56 8b 90 01 03 8b 74 90 01 02 8b d1 03 c1 83 90 01 02 8a 90 01 02 30 90 01 01 41 3b 4c 90 01 02 75 90 01 01 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}