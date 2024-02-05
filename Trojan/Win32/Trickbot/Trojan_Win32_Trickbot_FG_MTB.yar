
rule Trojan_Win32_Trickbot_FG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 90 01 01 8a 44 90 01 02 8a 90 01 02 32 90 01 01 8b 90 01 06 88 90 01 02 47 3b f8 72 90 0a 59 00 8d 90 02 02 99 b9 90 01 04 f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}