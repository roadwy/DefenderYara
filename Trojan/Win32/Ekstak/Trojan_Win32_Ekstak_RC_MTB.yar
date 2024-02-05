
rule Trojan_Win32_Ekstak_RC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 ff 15 a8 f0 46 00 56 ff 15 00 f2 46 00 85 c0 74 07 56 ff 15 a4 f0 46 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 33 c0 80 e2 3f 8a c2 0d c0 ff 00 00 83 c4 0c c3 90 90 90 90 55 8b ec ff 15 10 53 65 00 e8 82 ff ff ff e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 29 ff 15 a4 92 65 00 85 c0 a3 e0 ca 65 00 74 18 56 8b 75 14 68 a8 bb 45 01 56 ff 15 50 90 65 00 56 ff 15 4c 90 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 a3 90 01 03 00 e8 90 01 01 00 00 00 6a 00 6a 01 e8 90 09 19 00 6a 32 e8 90 01 03 00 01 05 90 01 03 00 e8 90 01 03 00 8b c8 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 46 07 00 00 59 a3 90 01 01 0b 08 01 e8 90 01 01 07 00 00 8b c8 33 d2 b8 90 01 04 f7 f1 31 05 7c 0b 08 01 e8 90 01 01 0d 00 00 33 c0 50 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 03 c8 89 0d 90 01 03 00 e8 90 01 03 00 8b c8 b8 90 01 04 33 d2 8b 1d 90 01 03 00 f7 f1 33 d8 89 1d 90 01 03 00 e8 90 09 0d 00 6a 32 e8 90 01 03 00 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 e8 6b a0 20 00 56 ff 15 54 66 65 00 ff 15 58 66 65 00 e9 } //01 00 
		$a_01_1 = {46 00 6f 00 6c 00 64 00 41 00 6c 00 79 00 7a 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 e8 a9 96 20 00 56 ff 15 a8 51 65 00 ff 15 ac 51 65 00 e9 } //01 00 
		$a_01_1 = {46 00 69 00 6c 00 65 00 41 00 6c 00 79 00 7a 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 3b 7d 0c a9 00 00 80 00 57 e8 90 01 01 8d 06 00 e9 90 00 } //01 00 
		$a_01_1 = {43 00 4a 00 6e 00 67 00 42 00 61 00 63 00 6b 00 75 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RC_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 01 05 55 8b ec 56 8b 75 14 56 6a 00 ff 15 90 01 01 67 65 00 56 e8 90 01 02 20 00 e9 90 00 } //01 00 
		$a_01_1 = {53 00 68 00 72 00 65 00 64 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}