
rule Trojan_Win32_Injuke_RB_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 05 c4 bd 65 00 e8 90 01 01 55 17 00 8b c8 b8 90 01 04 33 d2 f7 f1 a3 a8 bc 65 00 e8 2b 00 00 00 6a 00 6a 01 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Injuke_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 03 c8 89 0d e4 cd 46 00 e8 90 01 01 63 02 00 8b c8 b8 90 01 04 33 d2 8b 1d c8 90 01 01 46 00 f7 f1 33 d8 89 1d c8 cc 46 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Injuke_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 05 bc 1d 47 00 e8 90 01 01 8c 02 00 8b c8 b8 90 01 04 33 d2 f7 f1 a3 a0 1c 47 00 e8 90 01 01 48 fe ff 8b 15 a8 1a 47 00 a1 b8 1a 47 00 52 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Injuke_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 05 bc 3d 47 00 e8 90 01 01 8c 02 00 8b c8 b8 90 01 04 33 d2 f7 f1 a3 a0 3c 47 00 e8 90 01 01 47 fe ff 8b 15 a8 3a 47 00 a1 b8 3a 47 00 52 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Injuke_RB_MTB_5{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 05 bc 3d 47 00 e8 c3 8c 02 00 8b c8 b8 90 01 04 33 d2 f7 f1 a3 a0 3c 47 00 e8 90 01 02 fe ff 8b 15 a8 3a 47 00 a1 b8 3a 47 00 52 50 e8 90 01 02 03 00 90 00 } //01 00 
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 45 00 6d 00 70 00 74 00 79 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}