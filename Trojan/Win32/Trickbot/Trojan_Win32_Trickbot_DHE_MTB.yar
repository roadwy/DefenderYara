
rule Trojan_Win32_Trickbot_DHE_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 8d 0c 07 8b c7 f7 75 90 01 01 8b 45 90 01 01 8a 04 50 30 01 90 02 03 3b 7d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}