
rule Trojan_Win32_TrickBot_BB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 50 01 8a 08 40 84 c9 75 f9 2b c2 8b f8 33 c9 8b c1 33 d2 f7 f7 41 8a 82 90 01 04 30 44 31 ff 81 f9 60 11 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_BB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c5 99 bd f1 17 00 00 f7 fd 8b ea 8d 04 29 50 56 89 44 24 90 01 01 e8 90 01 04 8b 54 24 90 01 01 0f b6 0a 0f b6 06 03 c1 99 b9 f1 17 00 00 f7 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}