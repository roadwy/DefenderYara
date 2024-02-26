
rule Trojan_Win32_Ekstak_RE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 8b 45 14 50 ff 15 e8 94 65 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 56 e8 16 65 fb ff e9 } //01 00 
		$a_03_1 = {40 00 00 40 2e 90 01 01 64 65 78 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 4d b0 e8 f0 93 07 00 68 9c 20 6b 00 8d 4d b0 e8 43 94 07 00 b9 41 00 00 00 33 c0 bf a4 29 72 00 f3 ab } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 01 05 55 8b ec 56 8b 75 14 56 ff 15 90 01 02 65 00 56 e8 90 01 02 20 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 e8 36 65 fb ff e9 } //01 00 
		$a_01_1 = {53 8b 1d e4 33 65 00 56 8b 74 24 0c 57 6a 00 6a 00 6a 00 8d 46 1c 83 cf ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 57 68 71 69 4c 00 68 a4 30 4c 00 ff 15 3c 10 4c 00 50 e8 74 0d fd ff b9 41 00 00 00 33 c0 bf 00 65 4c 00 f3 ab } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 0c 66 33 c0 80 e1 3f 5e 8a c1 83 c8 c0 83 c4 10 c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec e8 58 ff ff ff e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 a3 90 01 03 00 e8 90 01 02 fe ff 8b 15 90 01 03 00 a1 90 01 03 00 52 50 e8 90 09 19 00 6a 32 e8 90 01 03 00 01 05 90 01 03 00 e8 90 01 03 00 8b c8 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}