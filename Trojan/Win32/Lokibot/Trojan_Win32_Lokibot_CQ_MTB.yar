
rule Trojan_Win32_Lokibot_CQ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 83 c1 01 89 4d fc 81 7d fc 90 01 02 00 00 73 90 01 01 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 90 02 06 0f be 0c 10 8b 55 fc 0f b6 90 01 06 33 c1 8b 4d fc 88 90 02 06 eb 90 00 } //01 00 
		$a_02_1 = {52 6a 40 68 90 01 02 00 00 90 02 08 ff 15 90 01 04 68 90 01 04 6a 90 01 01 6a 90 01 01 6a 90 01 01 68 90 01 04 90 02 06 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}