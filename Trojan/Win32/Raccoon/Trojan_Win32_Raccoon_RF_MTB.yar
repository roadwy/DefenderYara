
rule Trojan_Win32_Raccoon_RF_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 8b 44 24 08 33 44 24 0c 8b 4c 24 04 89 01 c2 0c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 08 31 04 24 8b 04 24 89 01 59 c2 08 00 90 02 08 81 00 e1 34 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 f7 f1 8b 45 fc 8a 0c 02 8d 14 33 8a 04 17 32 c1 43 88 02 } //01 00 
		$a_03_1 = {8b 45 fc f7 f1 8a 0e 8b 45 fc 32 8a 90 01 04 40 88 0c 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 08 89 55 f8 89 4d fc 8b 45 f8 c1 e0 04 8b 4d fc 89 01 8b e5 5d c3 90 02 20 8b 08 81 e9 1f cb 10 39 8b 55 fc 89 0a 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 90 01 01 38 dd 96 53 8b c6 90 02 40 8b d6 d3 ea 03 d5 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_9{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 4d 90 01 01 8b c7 d3 e0 89 5d 90 01 01 03 45 90 02 20 8b c7 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_10{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 55 8b ec 51 83 65 fc 00 83 45 fc 04 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 90 01 01 38 dd 96 53 8b c6 90 02 30 01 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 8b c6 d3 e8 8b 4c 24 90 01 01 31 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_12{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 4d 90 01 01 8b c7 d3 e0 90 02 30 8b c7 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_13{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 90 01 01 38 dd 96 53 8b 4c 24 90 01 01 8b d6 d3 e2 90 02 35 8b c6 d3 e8 03 c5 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 31 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_14{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 90 01 01 38 dd 96 53 8b c6 90 02 30 01 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 8b d6 d3 ea 03 d5 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RF_MTB_15{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 90 01 01 38 dd 96 53 8b c6 90 02 40 8b 54 24 90 01 01 31 54 24 90 01 01 8b c6 d3 e8 03 c3 90 02 30 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}