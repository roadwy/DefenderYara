
rule Trojan_Win32_lokibot_SI_MTB{
	meta:
		description = "Trojan:Win32/lokibot.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 e8 ?? ?? ?? ?? 90 05 10 01 90 43 4e 75 90 0a 80 00 8b ?? fc 03 ?? f8 90 05 10 01 90 8a ?? 90 05 10 01 90 90 05 10 02 34 80 [0-02] 90 05 10 01 90 88 ?? 90 05 10 01 90 8d 45 f8 e8 } //1
		$a_03_1 = {8b c2 03 c3 90 05 10 01 90 c6 00 ?? 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 ?? 90 05 10 01 90 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_lokibot_SI_MTB_2{
	meta:
		description = "Trojan:Win32/lokibot.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 ec 89 55 f8 89 45 fc [0-10] c6 45 ef f1 [0-10] 8b 45 fc 89 45 f4 8b 45 f4 8a 80 14 e0 47 00 30 45 ef 8b 45 f8 89 45 f0 [0-10] 8b 45 f0 8a 55 ef 88 10 [0-10] c3 } //1
		$a_03_1 = {8b 55 f4 8b 45 f8 e8 ?? ?? ff ff ff 45 f8 81 7d f8 ?? ?? 00 00 75 } //1
		$a_03_2 = {55 8b ec 83 c4 f8 89 55 fc 89 45 f8 [0-10] 8b 7d fc 03 7d f8 ff d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}