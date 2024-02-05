
rule Trojan_Win32_Zbot_GIL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 33 d2 8b 45 0c c1 e8 02 2b c1 50 f7 f3 83 c2 02 29 16 33 d2 58 f7 f3 03 14 24 81 c2 a0 82 f9 45 31 16 83 c6 04 e2 d9 } //00 00 
	condition:
		any of ($a_*)
 
}