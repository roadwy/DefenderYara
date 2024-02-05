
rule Trojan_Win32_Zbot_GWW_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 17 8b 74 24 14 0f b6 c3 8a 04 30 8b 74 24 1c 02 c2 02 c8 88 4c 24 11 0f b6 c9 fe c3 8a 04 31 88 07 88 14 31 0f b6 c3 33 d2 66 3b 44 24 12 0f b6 cb 0f 44 ca 47 8a d9 8a 4c 24 11 4d 75 c1 } //00 00 
	condition:
		any of ($a_*)
 
}