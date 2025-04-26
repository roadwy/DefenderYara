
rule Trojan_Win32_Trickbot_BZ_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.BZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 ec 33 c0 8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d e4 fe ff ff 33 c2 8b 4d 08 03 4d ec 88 01 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_BZ_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.BZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0e 8b c3 8b 51 0c 8b 59 14 2b d3 03 d7 66 0f b6 0a 8b d9 2b c8 66 85 c9 7d 06 81 c1 00 01 00 00 8b 85 30 ff ff ff 88 0a 03 f8 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}