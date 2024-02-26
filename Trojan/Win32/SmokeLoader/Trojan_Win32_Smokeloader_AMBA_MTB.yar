
rule Trojan_Win32_Smokeloader_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 45 cc 33 45 ec 33 c8 2b f1 83 6d e0 90 01 01 89 4d fc 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_AMBA_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 7d f0 8b d6 d3 ea 8d 04 37 89 45 ec c7 05 90 01 08 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 ec 90 00 } //05 00 
		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 75 f8 8b 4d f4 8d 04 37 31 45 fc d3 ee 03 75 d0 81 3d 90 01 04 21 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_AMBA_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 03 44 24 30 8b cf c1 e1 04 03 4c 24 2c 8d 14 2f 33 c1 33 c2 2b d8 8b c3 c1 e0 04 c7 05 90 01 08 89 44 24 14 8b 44 24 24 01 44 24 14 81 3d 90 01 04 be 01 00 00 90 00 } //01 00 
		$a_03_1 = {8d 04 2b 33 f0 8b 44 24 14 33 c6 2b f8 81 c5 90 01 04 ff 4c 24 1c 89 44 24 14 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}