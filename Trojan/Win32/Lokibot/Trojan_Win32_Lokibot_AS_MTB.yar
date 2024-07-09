
rule Trojan_Win32_Lokibot_AS_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 83 fb 00 74 ?? eb } //1
		$a_03_1 = {89 e0 83 c4 06 ff 28 e8 ?? ?? ff ff c3 } //1
		$a_03_2 = {8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 e9 ?? 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}