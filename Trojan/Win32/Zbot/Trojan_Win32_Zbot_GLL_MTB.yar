
rule Trojan_Win32_Zbot_GLL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b fe 33 30 8b ff 8b 75 b8 81 c6 90 01 04 ba 90 01 04 81 f2 90 01 04 23 f2 b9 90 01 04 c1 c9 05 b8 90 01 04 35 90 01 04 e9 0b 01 00 00 90 00 } //0a 00 
		$a_01_1 = {33 07 33 c1 08 ff 8b ff 8b 16 8b 4d a0 81 f1 03 d4 f4 e4 03 f1 e9 f2 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}