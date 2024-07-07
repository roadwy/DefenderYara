
rule Trojan_Win32_Lokibot_AV_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8a 14 16 30 14 01 83 fe 14 75 04 33 f6 eb 01 46 30 1c 01 41 3b cf 72 e5 } //1
		$a_01_1 = {8a 54 35 e4 30 14 08 83 fe 14 75 04 33 f6 eb 01 46 40 3b c7 72 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Lokibot_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 c1 0f 85 90 01 01 ff ff ff 90 0a 20 00 8b 0f 90 02 06 31 f1 90 02 08 39 c1 0f 85 90 01 01 ff ff ff 90 00 } //1
		$a_03_1 = {83 c2 04 e9 90 01 01 00 00 00 90 0a 40 00 8b 0f 90 02 10 31 f1 90 02 10 11 0c 18 90 02 10 83 c2 04 e9 90 01 01 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}