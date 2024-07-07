
rule Trojan_Win32_Smokeloader_CCDK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ca 89 44 24 90 01 01 89 4c 24 90 01 01 89 35 90 01 04 8b 44 24 90 01 01 01 05 90 01 04 a1 90 01 04 89 44 24 90 01 01 89 74 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 54 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}