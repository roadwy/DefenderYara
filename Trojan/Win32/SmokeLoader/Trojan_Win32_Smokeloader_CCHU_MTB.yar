
rule Trojan_Win32_Smokeloader_CCHU_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 89 45 e8 89 7d ec 8b 45 e8 89 45 ec 8b 45 f8 31 45 ec 8b 45 ec 89 45 fc 8b 45 fc 29 45 f4 81 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}