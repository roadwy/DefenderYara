
rule Trojan_Win32_TrickBot_GA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 90 02 0a 8a 04 1a 30 04 31 41 3b cf 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 03 c1 99 b9 90 01 04 f7 f9 8b 45 90 01 01 83 c4 90 01 01 8a 8c 15 90 01 04 30 08 40 ff 4d 90 01 01 89 45 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}