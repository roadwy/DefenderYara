
rule Trojan_Win32_Smokeloader_HNI_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d a4 24 00 00 00 00 8b 15 90 01 04 89 54 24 10 b8 90 01 02 00 00 01 44 24 10 8b 44 24 10 8a 0c 30 8b 15 90 01 04 88 0c 32 81 3d 90 02 08 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}