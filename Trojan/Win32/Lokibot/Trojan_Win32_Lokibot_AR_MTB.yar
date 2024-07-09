
rule Trojan_Win32_Lokibot_AR_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {29 d2 03 11 bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 4a 39 1a eb } //1
		$a_03_1 = {89 d3 8b 0f 31 f1 [0-05] 11 0c 18 } //1
		$a_01_2 = {46 ff 37 59 31 f1 39 c1 75 } //1
		$a_01_3 = {01 c2 8b 1a ff d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Lokibot_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 ff 30 64 89 20 33 c0 a3 ?? ?? ?? 00 90 05 10 01 90 b8 00 00 00 00 f7 f0 } //1
		$a_03_1 = {ff 75 fc 5b 81 c3 ?? ?? 00 00 53 c3 } //1
		$a_03_2 = {8a 02 88 45 ?? 90 05 10 01 90 8b 84 9d ?? ?? ff ff 03 84 bd ?? ?? ff ff 90 05 10 01 90 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ff ff 32 45 ?? 8b 4d ?? 88 01 90 05 10 01 90 ff 45 ?? 42 ff 4d ?? 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}