
rule Trojan_Win32_Smokeloader_F_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 bc 56 c6 45 bd 69 8d 4d bc 51 } //01 00 
		$a_01_1 = {4c 65 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_F_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 90 01 04 88 0c 32 81 c4 04 10 00 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_F_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c6 50 68 90 01 04 e8 90 01 04 8b c6 83 c4 08 83 e0 03 8a 80 90 01 04 30 86 90 01 04 46 81 fe 90 01 04 72 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}