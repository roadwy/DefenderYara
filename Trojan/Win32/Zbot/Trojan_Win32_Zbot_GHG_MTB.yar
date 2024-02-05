
rule Trojan_Win32_Zbot_GHG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b ca 8b 49 3c c1 a4 25 90 01 04 06 8b 4c 11 78 03 ca 8b 49 0c 31 05 78 45 40 00 8a 14 11 fe ca 80 f2 2f 19 94 25 90 01 04 80 fa 65 0f 84 90 00 } //0a 00 
		$a_03_1 = {33 d7 33 d6 81 a4 25 90 01 04 55 1c 00 00 51 19 94 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}