
rule Trojan_Win32_Remcos_ARM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {86 0e 0a 01 01 b9 6c 01 01 01 67 8a 86 e9 e7 00 00 ba 66 01 01 01 67 8a 8e eb e7 00 00 bb 73 01 01 01 67 8a 96 ed e7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 03 5d a4 6a 00 e8 90 01 04 2b d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 90 01 04 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Remcos_ARM_MTB_3{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f0 8b 44 24 20 8b d0 03 f7 0b 54 24 24 23 54 24 28 23 44 24 24 0b d0 03 d6 8b 44 24 30 8b 74 24 14 83 c0 20 89 44 24 30 3d 00 01 00 00 8b 44 24 10 89 54 24 2c 89 54 24 34 } //00 00 
	condition:
		any of ($a_*)
 
}