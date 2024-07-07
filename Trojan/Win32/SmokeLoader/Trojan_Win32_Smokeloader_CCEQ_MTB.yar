
rule Trojan_Win32_Smokeloader_CCEQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 55 ff 15 90 01 04 8b 44 24 90 01 01 33 c6 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 90 01 01 24 90 01 01 89 6c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}