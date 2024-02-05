
rule Trojan_Win32_RedLine_RPX_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 51 59 58 88 04 0b eb 05 d1 5d 29 f5 38 50 b8 b7 00 00 00 eb 19 4c 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 20 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 55 d4 52 6a 40 8b 45 cc 50 68 90 01 04 ff 55 e8 89 45 d0 90 00 } //01 00 
		$a_03_1 = {8b 7d 08 33 db f6 17 80 37 90 01 01 47 e2 f6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b d6 d3 ea 03 54 24 30 89 54 24 14 8b 44 24 20 31 44 24 10 8b 44 24 10 33 44 24 14 2b f8 89 44 24 10 8d 44 24 24 89 7c 24 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 8b 0e 8b 49 04 8b 4c 31 30 8b 49 04 89 4c 24 0c 8b 11 ff 52 04 8d 44 24 08 50 e8 90 01 04 83 c4 04 8b 08 6a 0a 8b 51 30 8b c8 ff d2 8b 4c 24 0c 0f b7 f8 85 c9 74 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 fb 0f be 4d fb 0f be 75 fb 8b 45 fc 99 bf 37 00 00 00 f7 ff 8b 45 08 0f be 04 10 69 c0 53 0b 00 00 99 bf 34 00 00 00 f7 ff 25 70 29 00 00 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 83 c0 01 89 45 dc 8b 4d dc 3b 4d 10 73 30 8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 69 c9 19 14 00 00 83 e1 45 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb bf } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_RPX_MTB_8{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 50 ff 74 24 50 ff 54 24 34 8b 44 24 18 47 8b 54 24 14 83 c6 28 0f b7 80 90 01 04 3b f8 7c bc 8b 7c 24 2c 8b 74 24 1c 8b 86 a4 00 00 00 6a 00 6a 04 ff 74 24 44 83 c0 08 50 ff 74 24 50 ff 54 24 34 8b 4c 24 18 56 8b 81 90 01 04 03 44 24 18 89 86 b0 00 00 00 ff 74 24 48 ff 54 24 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}