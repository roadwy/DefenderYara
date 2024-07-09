
rule Trojan_Win32_Smokeloader_Y_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f0 33 45 ?? 31 45 ?? 8b 45 fc 29 45 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Smokeloader_Y_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 45 ?? 01 45 f8 8b 45 f8 31 45 ec 8b 4d f0 8b 45 ec 33 c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}