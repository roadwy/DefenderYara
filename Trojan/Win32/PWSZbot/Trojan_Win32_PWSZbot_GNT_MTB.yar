
rule Trojan_Win32_PWSZbot_GNT_MTB{
	meta:
		description = "Trojan:Win32/PWSZbot.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {55 33 07 08 8b 90 01 04 c1 c0 90 01 01 ba 90 01 04 c1 ca 15 03 c2 c1 c8 16 89 45 b8 e9 d3 01 00 00 90 00 } //0a 00 
		$a_02_1 = {8b f8 23 fa 3b fa 0f 85 90 01 04 c1 e1 90 01 01 c1 e0 90 01 01 eb ec 41 33 df 90 00 } //01 00 
		$a_01_2 = {68 4f 70 74 6e 52 65 65 } //01 00 
		$a_01_3 = {64 33 64 38 74 68 6b 2e 64 6c 6d } //00 00 
	condition:
		any of ($a_*)
 
}