
rule Trojan_Win32_Qakbot_AR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 8b 55 fc 8d 84 0a 59 11 00 00 89 45 f0 8b 0d 90 01 04 89 0d 90 01 04 8b 55 f0 89 15 90 01 04 8b 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 fd 8a 67 00 89 4d f8 8b 55 f8 81 ea fd 8a 67 00 89 55 f8 b8 23 5f ff ff 03 05 90 01 04 8b 80 19 a1 00 00 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 61 64 37 35 65 33 30 30 32 38 31 32 33 31 65 } //01 00 
		$a_01_1 = {34 66 31 38 39 32 34 38 33 39 62 63 39 65 63 30 } //01 00 
		$a_01_2 = {61 30 37 38 38 65 61 62 64 31 36 66 36 34 39 37 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10 90 00 } //02 00 
		$a_00_1 = {8b 55 08 8b 02 2b c1 8b 4d 08 89 01 5e 8b e5 5d } //00 00 
		$a_00_2 = {78 4a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {56 8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10 90 00 } //02 00 
		$a_00_1 = {03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d } //00 00 
		$a_00_2 = {78 63 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 fd 8a 67 00 89 4d f8 8b 55 f8 81 ea fd 8a 67 00 89 55 f8 b8 3b bb fa ff 03 05 90 01 04 8b 80 01 45 05 00 a3 90 00 } //01 00 
		$a_02_1 = {03 4d f4 03 4d f4 8b 15 90 01 04 8b 35 90 01 04 8a 04 06 88 04 0a 8b 0d 90 01 04 83 c1 01 89 0d 90 01 04 eb 98 90 00 } //00 00 
		$a_00_2 = {78 } //82 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 75 69 6c 64 61 62 6c 65 } //01 00 
		$a_01_1 = {65 75 6f 72 6e 69 74 68 69 63 } //01 00 
		$a_01_2 = {70 61 72 61 6e 69 74 72 6f 73 6f 70 68 65 6e 6f 6c } //01 00 
		$a_01_3 = {70 68 6f 74 6f 73 79 6e 74 68 65 74 69 63 61 6c 6c 79 } //01 00 
		$a_01_4 = {70 73 65 70 68 6f 6d 61 6e 63 79 } //01 00 
		$a_01_5 = {73 63 79 70 68 6f 73 74 6f 6d 61 } //01 00 
		$a_01_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 75 f4 03 c6 03 45 f4 8b 0d 90 01 04 03 4d f4 03 4d f4 03 4d f4 8b 15 90 01 04 8b 35 90 01 04 8a 04 06 88 04 0a 8b 0d 90 01 04 83 c1 01 89 0d 90 00 } //01 00 
		$a_03_1 = {8b d2 8b d2 a1 90 01 04 8b d2 8b 0d 90 01 04 8b d2 a3 90 01 04 8b c0 a1 90 01 04 a3 90 00 } //01 00 
		$a_03_2 = {8b d2 8b 35 90 01 04 33 f1 90 02 08 c7 05 90 02 08 01 35 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //00 00 
		$a_00_3 = {78 } //b7 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 75 f4 03 c6 03 45 f4 8b 0d 90 01 04 03 4d f4 03 4d f4 03 4d f4 8b 15 90 01 04 8b 35 90 01 04 8a 04 06 88 04 0a 8b 0d 90 01 04 83 c1 01 89 0d 90 00 } //01 00 
		$a_03_1 = {8b d2 8b d2 8b d2 a1 90 01 04 8b d2 8b 0d 90 01 04 8b d2 a3 90 01 04 8b c0 a1 90 01 04 a3 90 01 04 31 0d 90 01 04 c7 05 90 01 08 8b 1d 90 01 04 01 1d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_03_2 = {8b d2 8b d2 8b 15 90 01 04 31 0d 90 02 08 c7 05 90 02 08 8b 1d 90 01 04 01 1d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5b 5d 90 00 } //00 00 
		$a_00_3 = {78 } //25 01 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 75 f4 03 c6 03 45 f4 8b 15 90 01 04 03 55 f4 03 55 f4 03 55 f4 8b 0d 90 01 04 8b 35 90 01 04 8a 04 06 88 04 11 8b 0d 90 01 04 83 c1 01 89 0d 90 00 } //01 00 
		$a_03_1 = {8b d2 8b d2 a1 90 01 04 8b d2 8b 0d 90 01 04 8b d2 a3 90 01 04 8b c0 a1 90 01 04 a3 90 00 } //01 00 
		$a_03_2 = {b8 bc 01 00 00 b8 bc 01 00 00 31 0d 90 02 08 c7 05 90 02 08 a1 90 01 04 01 05 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_03_3 = {b8 bc 01 00 00 b8 bc 01 00 00 31 0d 90 01 04 eb 90 02 04 c7 05 90 02 08 ff 35 90 01 04 5a 01 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_03_4 = {b8 bc 01 00 00 31 0d 90 01 04 eb 00 c7 05 90 02 08 8b 35 90 01 04 01 35 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_03_5 = {b8 bc 01 00 00 b8 bc 01 00 00 31 0d 90 01 04 eb 00 c7 05 90 01 04 00 00 00 00 90 02 46 a1 90 01 04 8b 0d 90 01 04 89 08 90 03 01 01 5e 5d 90 00 } //00 00 
		$a_00_6 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 f0 8b 45 08 8b 08 2b ce 8b 55 08 89 0a 5e 8b e5 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 8c 06 c2 5a 00 00 8b 55 08 89 0a } //02 00 
		$a_01_1 = {8b 45 08 8b 08 2b ce 8b 55 08 89 0a } //00 00 
		$a_01_2 = {00 61 } //4f 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AR_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 f5 30 de bc e8 98 20 0b 14 34 0a eb ba 64 a1 97 57 2c 61 4c 37 ad } //01 00 
		$a_01_1 = {19 36 00 0b 97 37 ff 47 20 3e 8b 06 } //01 00 
		$a_01_2 = {83 74 d0 38 5f 74 da b9 51 a2 4e 4f 53 ed 38 5c 5f ef b9 5d 62 de 2e 08 7a 57 } //00 00 
	condition:
		any of ($a_*)
 
}