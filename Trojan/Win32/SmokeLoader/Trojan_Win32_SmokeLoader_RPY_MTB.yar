
rule Trojan_Win32_SmokeLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 d3 e8 8b 4c 24 10 03 c5 89 44 24 14 33 44 24 20 33 c8 8d 44 24 28 89 4c 24 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 89 5d f4 8b 45 e8 01 45 f4 8b 45 d0 90 01 45 f4 8b 45 f4 89 45 ec 8b 4d f0 8b c6 d3 e8 8b 4d ec 31 4d fc 03 45 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 60 02 00 00 ea 13 30 0a c7 84 24 74 02 00 00 0a 4b 19 39 c7 84 24 04 03 00 00 3e 5c d5 18 c7 84 24 c8 01 00 00 e9 d6 86 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_5{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 6a 40 8b 85 58 ff ff ff ff 70 0a ff b5 50 ff ff ff ff 55 d8 89 45 f4 8b 85 50 ff ff ff 89 85 68 ff ff ff 8b 85 58 ff ff ff ff 70 0a 6a 00 ff b5 50 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_6{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 0e fc ff ff 33 c6 85 11 fc ff ff 6e c6 85 06 fc ff ff 54 c6 85 13 fc ff ff 70 c6 85 0f fc ff ff 32 c6 85 01 fc ff ff 72 c6 85 09 fc ff ff 6c c6 85 15 fc ff ff 68 c6 85 14 fc ff ff 73 c6 85 04 fc ff ff 74 c6 85 12 fc ff ff 61 c6 85 10 fc ff ff 53 c6 85 03 fc ff ff 61 c6 85 18 fc ff ff 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}