
rule Trojan_Win32_Lokibot_AN_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1 eb } //1
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 08 89 c8 eb } //1
		$a_03_2 = {66 31 0c 18 81 fb 90 01 02 00 00 7d 05 83 c3 02 eb 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Lokibot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 90 01 01 00 00 68 90 01 02 00 00 6a 00 e8 90 01 04 50 e8 90 01 04 89 45 f8 33 c0 89 45 f4 ba 90 01 04 8a 02 88 45 ff b0 90 01 01 8a 5d ff 32 c3 8b 7d f8 03 7d f4 88 07 ff 45 f4 42 81 7d f4 90 01 02 00 00 75 df 90 01 01 00 00 00 00 90 02 04 00 00 03 90 01 01 f8 ff 90 01 01 8b e5 5d c2 04 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}