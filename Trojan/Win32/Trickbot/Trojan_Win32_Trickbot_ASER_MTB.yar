
rule Trojan_Win32_Trickbot_ASER_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.ASER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {05 00 00 80 34 1e 90 01 01 68 90 01 03 00 e8 90 01 03 00 80 04 1e 90 01 01 68 90 01 03 00 e8 90 01 03 00 80 04 1e 90 01 01 83 c4 40 68 90 01 03 00 e8 90 01 03 00 80 04 1e 90 01 01 83 c4 04 46 3b f7 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}