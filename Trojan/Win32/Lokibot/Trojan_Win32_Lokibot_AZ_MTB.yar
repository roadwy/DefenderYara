
rule Trojan_Win32_Lokibot_AZ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 29 c9 eb 06 90 05 10 01 00 85 c0 eb 90 05 10 01 00 43 eb 90 05 10 01 00 66 81 fa ?? ?? eb 90 05 10 01 00 0b 0f eb 90 05 10 01 00 66 81 fb ?? ?? eb 90 05 10 01 00 31 d9 eb 90 05 10 01 00 85 c0 eb 90 05 10 01 00 39 c1 eb 90 05 10 01 00 75 9c 66 81 fa ?? ?? eb } //1
		$a_03_1 = {29 c9 eb 01 [0-10] 43 eb [0-10] 0b 0f eb [0-10] 31 d9 eb [0-10] 39 c1 75 ?? eb [0-10] eb [0-10] 89 de eb [0-10] eb [0-10] 48 b9 ?? ?? ?? 00 eb [0-10] eb [0-10] 81 f1 ?? ?? ?? 00 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Lokibot_AZ_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AZ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 e9 38 26 00 00 } //1
		$a_01_1 = {56 8b f1 85 f6 0f 84 1e 00 00 00 33 c9 41 2b c8 57 8b 7c 24 0c 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 4e 0f 85 e9 ff ff ff 5f 5e c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}