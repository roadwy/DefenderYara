
rule Trojan_Win32_SmokeLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 c6 89 45 fc 2b f8 8b 45 cc 29 45 f8 83 6d e0 01 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 14 33 83 ff 0f 75 4d 6a 00 6a 00 6a 00 ff d5 6a 2e 8d 44 24 10 6a 00 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d f8 fb ff ff 30 04 39 83 fb 0f 75 1f 56 8d 85 fc fb ff ff 50 56 56 56 56 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 75 05 74 03 e3 1c 2c 8b 1c 24 83 c4 04 eb 0a 08 81 eb dc 32 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 04 8d 8d 78 ff ff ff 51 8b 8f a4 00 00 00 83 c1 08 51 ff 75 90 ff d0 8b 45 ac 6a 40 68 00 30 00 00 8d 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 ff d6 ff d7 4b 75 f7 } //1
		$a_01_1 = {56 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d3 6a 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 45 f0 8b 45 f8 33 45 f0 2b f0 89 45 f8 8b c6 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f4 8d 04 33 89 45 e8 8b c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_8{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8 c1 e2 04 89 55 fc 8b 45 e4 01 45 fc 8b 4d f8 8b f1 c1 ee 05 03 75 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_9{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 20 8b 44 24 20 89 44 24 18 8b 4c 24 28 8b c7 d3 e8 89 44 24 14 8b 44 24 ?? 01 44 24 14 8b 44 24 14 33 44 24 18 31 44 24 10 8b 44 24 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RPX_MTB_10{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 83 65 f0 00 8b 45 e8 01 45 f0 8b 45 e4 90 01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c7 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}