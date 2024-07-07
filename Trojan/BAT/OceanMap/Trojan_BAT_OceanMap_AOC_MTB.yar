
rule Trojan_BAT_OceanMap_AOC_MTB{
	meta:
		description = "Trojan:BAT/OceanMap.AOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 38 09 11 04 9a 13 05 11 05 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 2d 1e 08 11 05 17 8d 90 01 01 00 00 01 25 16 1f 29 9d 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 0c 11 04 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}