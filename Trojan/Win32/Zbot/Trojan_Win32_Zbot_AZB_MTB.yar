
rule Trojan_Win32_Zbot_AZB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 60 05 00 8b 07 09 c0 74 45 8b 5f 04 8d 84 30 60 9a 05 00 01 f3 50 83 c7 08 ff 96 24 9b 05 00 95 8a 07 47 } //00 00 
	condition:
		any of ($a_*)
 
}