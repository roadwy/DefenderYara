
rule Trojan_Win32_Zbot_SIBE19_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBE19!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 ed ba 00 00 00 00 01 fa b8 90 01 04 01 f8 89 c7 89 44 24 90 01 01 be 90 01 04 01 c6 80 38 90 01 01 75 90 01 01 8a 0a 88 08 42 81 fd 90 01 04 7d 90 01 01 8a 0a c0 e1 90 01 01 08 08 42 45 40 39 c6 75 90 00 } //01 00 
		$a_02_1 = {5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 90 01 01 75 90 01 01 31 c9 83 ea 90 01 01 47 39 f8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}