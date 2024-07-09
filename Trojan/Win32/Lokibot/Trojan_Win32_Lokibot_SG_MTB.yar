
rule Trojan_Win32_Lokibot_SG_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 03 55 f8 90 05 0a 01 90 8a 03 90 05 0a 01 90 34 ?? 90 05 0a 01 90 88 02 90 05 0a 01 90 8d 45 f8 e8 ?? ?? ?? ?? 90 05 0a 01 90 43 4e 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Lokibot_SG_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 e8 53 56 57 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 e8 44 0e f9 ff 89 45 fc [0-05] 8b 45 fc 89 45 f8 [0-04] 8d 45 e8 50 e8 [0-10] 8b 45 f8 3b 45 fc 0f } //1
		$a_03_1 = {8b d3 8b c6 e8 ?? ?? ff ff 46 81 fe ?? ?? 00 00 75 } //1
		$a_03_2 = {8d 55 e8 8d 45 f0 e8 ?? ?? ff ff 8b c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}