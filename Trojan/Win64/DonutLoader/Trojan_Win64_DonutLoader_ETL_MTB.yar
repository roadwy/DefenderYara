
rule Trojan_Win64_DonutLoader_ETL_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 20 48 8d 0d 37 11 00 00 0f be 04 01 89 44 24 24 8b 44 24 20 99 83 e0 01 33 c2 2b c2 48 98 48 8b 4c 24 38 0f be 04 01 8b 4c 24 24 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 30 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}