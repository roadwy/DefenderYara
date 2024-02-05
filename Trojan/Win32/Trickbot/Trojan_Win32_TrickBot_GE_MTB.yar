
rule Trojan_Win32_TrickBot_GE_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 74 24 10 74 90 02 0c 8b 44 24 10 8d 0c 06 33 d2 6a 90 01 01 8b c6 90 01 01 f7 90 01 01 8b 44 24 90 01 01 8a 04 02 30 01 46 3b 74 24 14 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_GE_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 44 24 1f 0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 09 f0 88 44 24 1e c7 44 24 40 91 00 00 00 8a 44 24 17 0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 31 f0 88 44 24 1e } //01 00 
		$a_81_1 = {54 79 72 65 44 6f 6b 67 57 } //00 00 
	condition:
		any of ($a_*)
 
}