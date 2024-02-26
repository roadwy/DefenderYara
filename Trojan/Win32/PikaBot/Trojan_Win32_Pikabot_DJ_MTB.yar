
rule Trojan_Win32_Pikabot_DJ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 35 90 01 01 32 44 19 90 01 01 88 43 90 01 01 8d 04 1f 3d 00 f6 02 00 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}