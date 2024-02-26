
rule Trojan_Win32_Pikabot_ZX_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 47 01 0f b6 f8 8a 8c 3d 90 01 04 0f b6 d1 8d 04 13 0f b6 d8 8a 84 1d 90 01 04 88 84 3d 90 01 04 88 8c 1d 90 01 04 0f b6 84 3d 90 01 04 03 c2 0f b6 c0 8a 84 05 90 01 04 32 44 35 d0 88 84 35 90 01 04 46 83 fe 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}