
rule Trojan_Win32_Cridex_AR_MTB{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c2 08 79 03 01 a1 90 01 04 89 13 83 c3 04 2b c1 83 6c 24 10 01 75 b3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 20 69 d2 34 50 01 00 05 40 26 00 01 89 44 24 20 89 01 8b 4c 24 18 a3 90 01 04 03 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 f8 d1 5f 01 00 0f b6 05 90 01 04 8d 0c 51 81 c1 a4 c1 fe ff 03 ce 89 0d 90 01 04 3b c7 77 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_4{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 14 8b c2 2b c3 81 c6 f0 25 08 01 83 e8 30 89 35 90 01 04 89 31 8d 1c 45 09 00 00 00 39 7c 24 2c 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c6 2b c3 83 e8 04 2b 44 24 28 83 44 24 18 04 83 c0 da 8b 3d 90 01 04 03 c6 83 6c 24 1c 01 89 44 24 14 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_6{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c3 2c 8f 04 01 89 1a 0f b7 2d 90 01 04 8b d0 2b d7 0f b7 3d 90 01 04 2b fd 81 ea 12 9d 00 00 a3 90 01 04 81 ff 67 01 00 00 75 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_7{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 b6 0c 0c 00 b8 b6 0c 0c 00 a1 90 01 04 a3 90 01 04 31 0d 90 01 04 c7 05 90 01 08 a1 90 01 04 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 5f 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_8{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 81 c1 08 e8 02 01 89 0a 8b 15 90 01 04 89 0d 90 01 04 8b 0d 90 01 04 03 ca 90 00 } //01 00 
		$a_02_1 = {8b 7c 24 2c 81 c2 78 41 0c 01 8b 74 24 1c 83 c6 3b 89 54 24 18 03 f0 89 15 90 01 04 89 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_9{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 74 24 20 8d 34 09 2b f0 8b ca 81 c6 71 f2 fe ff 03 f2 33 d2 89 74 24 34 85 c9 0f 94 c2 89 54 24 3c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cridex_AR_MTB_10{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 51 03 05 2c f9 04 01 03 d6 89 45 00 6b ca 52 83 c5 04 2b cf 03 f1 83 6c 24 } //01 00 
		$a_01_1 = {83 44 24 10 04 81 c3 90 4b 08 01 69 c1 3e 5c 01 00 89 1e 8b f2 2b f0 2b 74 24 14 8d 4e 08 } //00 00 
	condition:
		any of ($a_*)
 
}