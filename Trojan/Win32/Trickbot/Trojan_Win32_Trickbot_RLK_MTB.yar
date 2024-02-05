
rule Trojan_Win32_Trickbot_RLK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e1 04 03 4d e4 8d 14 33 33 c1 33 c2 6a 00 2b f8 81 c3 47 86 c8 61 ff 15 90 01 04 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}