
rule Trojan_Win32_PonyStealer_AE_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c6 90 02 25 66 0f 6e c9 90 02 40 0f 7e c9 90 02 25 90 13 0f 77 90 02 25 46 90 02 25 8b 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_PonyStealer_AE_MTB_2{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c6 90 02 15 66 0f 6e c9 90 02 15 66 0f ef c8 90 02 15 66 0f 7e c9 90 02 25 90 13 0f 77 90 02 15 90 02 15 ff 37 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_PonyStealer_AE_MTB_3{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e d0 0f 6e d0 0f 6e d0 90 13 90 02 15 46 90 02 15 8b 0f 90 02 15 0f 6e c6 90 02 15 0f 6e c9 90 02 15 0f ef c8 90 02 15 0f 7e c9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_PonyStealer_AE_MTB_4{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 7e d2 85 90 02 25 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e d2 90 02 15 0f ef d7 90 02 15 c3 90 00 } //1
		$a_03_1 = {0f 7e d2 83 90 02 25 90 13 90 02 15 46 90 02 15 8b 17 90 02 25 90 18 0f 6e d2 90 02 15 0f ef d7 90 02 15 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_PonyStealer_AE_MTB_5{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 7e d2 66 90 02 25 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e d2 90 02 15 0f ef d7 90 02 15 c3 90 00 } //1
		$a_03_1 = {0f 7e d2 66 90 02 25 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 0f 6e d2 90 02 15 90 18 90 02 15 0f ef d7 90 02 15 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_PonyStealer_AE_MTB_6{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f 7e d2 85 90 02 30 90 13 90 02 15 46 90 02 15 8b 17 90 02 25 0f 6e fe 90 02 25 0f 6e d2 90 02 25 90 18 90 02 15 0f ef d7 90 02 25 c3 90 00 } //1
		$a_03_1 = {0f 7e d2 81 90 02 30 90 13 90 02 15 46 90 02 15 8b 17 90 02 25 0f 6e fe 90 02 25 0f 6e d2 90 02 25 90 18 90 02 15 0f ef d7 90 02 25 c3 90 00 } //1
		$a_03_2 = {0f 7e d2 83 90 02 30 90 13 90 02 15 46 90 02 15 8b 17 90 02 25 0f 6e fe 90 02 25 0f 6e d2 90 02 25 90 18 90 02 15 0f ef d7 90 02 25 c3 90 00 } //1
		$a_03_3 = {0f 7e d2 66 90 02 30 90 13 90 02 15 46 90 02 15 8b 17 90 02 25 0f 6e fe 90 02 25 0f 6e d2 90 02 25 90 18 90 02 15 0f ef d7 90 02 25 c3 90 00 } //1
		$a_03_4 = {0f 7e d2 3d 90 02 30 90 13 90 02 15 46 90 02 15 8b 17 90 02 25 0f 6e fe 90 02 25 0f 6e d2 90 02 25 90 18 90 02 15 0f ef d7 90 02 25 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}
rule Trojan_Win32_PonyStealer_AE_MTB_7{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {0f 6e da 3d 90 02 40 31 f1 90 00 } //6
		$a_03_1 = {0f 6e da 81 90 02 40 31 f1 90 00 } //6
		$a_03_2 = {0f 6e da 66 90 02 40 31 f1 90 00 } //6
		$a_03_3 = {0f 6e da 83 90 02 40 31 f1 90 00 } //6
		$a_03_4 = {0f 6e da 85 90 02 40 31 f1 90 00 } //6
		$a_03_5 = {0f 6e da eb 90 02 40 31 f1 90 00 } //6
		$a_01_6 = {43 00 78 00 73 00 4d 00 33 00 63 00 4f 00 32 00 7a 00 37 00 30 00 56 00 51 00 4a 00 32 00 72 00 48 00 63 00 4b 00 38 00 69 00 43 00 63 00 57 00 44 00 73 00 67 00 66 00 71 00 67 00 42 00 64 00 58 00 45 00 48 00 6d 00 74 00 74 00 6c 00 32 00 34 00 30 00 } //1 CxsM3cO2z70VQJ2rHcK8iCcWDsgfqgBdXEHmttl240
		$a_01_7 = {54 00 30 00 4a 00 69 00 41 00 61 00 49 00 61 00 4a 00 4b 00 68 00 4e 00 35 00 62 00 46 00 4e 00 54 00 42 00 33 00 56 00 55 00 42 00 67 00 31 00 49 00 63 00 4a 00 35 00 6a 00 62 00 48 00 4b 00 59 00 79 00 45 00 4e 00 69 00 31 00 31 00 } //1 T0JiAaIaJKhN5bFNTB3VUBg1IcJ5jbHKYyENi11
		$a_01_8 = {44 00 56 00 55 00 7a 00 65 00 36 00 52 00 44 00 79 00 4b 00 66 00 49 00 4a 00 37 00 46 00 62 00 77 00 75 00 78 00 4a 00 42 00 70 00 43 00 67 00 34 00 36 00 76 00 57 00 65 00 63 00 45 00 77 00 36 00 36 00 } //1 DVUze6RDyKfIJ7FbwuxJBpCg46vWecEw66
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*6+(#a_03_2  & 1)*6+(#a_03_3  & 1)*6+(#a_03_4  & 1)*6+(#a_03_5  & 1)*6+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}