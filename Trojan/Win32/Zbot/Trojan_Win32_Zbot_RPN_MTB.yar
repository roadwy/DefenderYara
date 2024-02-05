
rule Trojan_Win32_Zbot_RPN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 32 50 57 53 5f 56 58 ab 5f 58 83 2b 01 f7 d9 f8 19 0b ff 32 8d 52 04 8d 5b 04 59 f3 0f c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RPN_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 14 03 0f b6 55 db 89 55 bc 8b 7d e4 89 f0 89 45 c0 89 d1 80 c9 01 31 d2 f7 f1 89 45 b8 8b 55 bc 89 c1 01 d1 89 ca 88 14 3b } //00 00 
	condition:
		any of ($a_*)
 
}