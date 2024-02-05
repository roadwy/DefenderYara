
rule Trojan_Win32_Zbot_AL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {28 13 43 c1 ea 08 41 83 f9 04 75 0a ba 72 c6 0e de b9 00 00 00 00 81 fb 9f fa 40 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_AL_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.AL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 5c 0d a8 8b 45 d4 30 1c 10 41 83 f9 13 76 02 33 c9 42 3b 56 04 72 e8 } //01 00 
		$a_01_1 = {8a 14 39 88 14 31 41 3b c8 72 f5 83 65 e4 00 33 c0 66 3b 43 06 73 3f } //00 00 
	condition:
		any of ($a_*)
 
}