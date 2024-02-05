
rule Trojan_Win32_Ekstak_RB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 08 a3 e0 ca 65 00 ff 15 54 95 65 00 a1 e0 ca 65 00 85 c0 74 13 68 a8 bb 45 01 56 ff 15 58 90 65 00 56 ff 15 54 90 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 6a 00 ff 15 50 67 65 00 56 e8 18 a1 20 00 e9 } //01 00 
		$a_01_1 = {53 00 68 00 72 00 65 00 64 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 ff 15 70 f0 46 00 8b 75 14 68 50 1c 27 01 56 ff 15 58 f0 46 00 e9 } //01 00 
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 50 ff 15 94 f0 46 00 ff 15 90 01 01 f0 46 00 3d 90 01 04 75 05 e8 21 b1 01 00 e9 90 00 } //01 00 
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}