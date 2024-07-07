
rule Trojan_Win32_Smokeloader_AMBD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 55 dc 8b 45 f0 31 45 fc 33 55 fc 89 55 f0 8b 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Smokeloader_AMBD_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 40 01 44 24 24 8b 44 24 14 33 44 24 24 89 44 24 24 8b 54 24 24 89 54 24 24 8b 44 24 24 29 44 24 1c 8b 4c 24 1c 8b 74 24 18 8b c1 c1 e0 04 03 44 24 48 03 f1 81 3d 90 01 04 be 01 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}