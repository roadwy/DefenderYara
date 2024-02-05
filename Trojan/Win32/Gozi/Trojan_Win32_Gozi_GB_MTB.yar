
rule Trojan_Win32_Gozi_GB_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 4d f0 8b 55 fc 8d 84 0a 90 02 15 89 45 90 01 01 8b 0d 90 01 04 89 0d 90 01 04 8b 55 90 01 01 89 15 90 00 } //01 00 
		$a_02_1 = {8b ff c7 05 90 02 20 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {34 5c 68 62 0c 02 10 c3 } //05 00 
		$a_00_1 = {c0 c0 07 68 1b 26 02 10 c3 } //05 00 
		$a_00_2 = {68 20 d0 01 10 68 20 d0 01 10 b8 a6 31 02 10 ff d0 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //VirtualProtectEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {99 33 ff 4d 2b c5 1b d7 8b 7c 24 90 01 01 2b c1 1b d6 8b c8 8b f2 8b c7 05 90 02 04 8a 10 8b 44 24 90 01 01 88 97 90 02 04 8b d1 2b d0 83 ea 04 0f b7 d2 47 90 00 } //0a 00 
		$a_02_1 = {2a cb 89 37 80 e9 90 01 01 83 c7 04 83 6c 24 90 01 01 01 89 35 90 01 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b d0 66 89 15 90 01 04 0f b6 05 90 01 04 8b 0d 90 01 04 8d 54 01 90 01 01 89 15 90 01 04 8b 45 90 01 01 83 e8 90 01 01 0f b7 0d 90 01 04 2b c1 8b 15 90 01 04 2b d0 89 15 90 01 04 8b 75 90 01 01 81 c2 90 01 04 83 c6 03 03 d0 83 ee 03 81 ea 90 01 04 ff e6 90 00 } //0a 00 
		$a_02_1 = {64 a1 00 00 00 00 50 83 c4 f0 53 56 57 a1 90 01 04 31 45 90 01 01 33 c5 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}