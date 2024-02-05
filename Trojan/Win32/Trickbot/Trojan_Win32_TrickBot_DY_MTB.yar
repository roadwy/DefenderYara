
rule Trojan_Win32_TrickBot_DY_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 19 03 d6 0f b6 c3 03 c2 33 d2 f7 f7 8b 7c 24 18 45 41 8b f2 8a 04 3e 88 41 ff 88 1c 3e } //01 00 
		$a_02_1 = {45 8b f2 8a 1c 0e 33 d2 0f b6 c3 03 c7 f7 35 90 01 04 8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 90 02 11 8a c3 f6 eb 8a 14 0a 2a d0 8b 44 24 18 30 54 28 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}