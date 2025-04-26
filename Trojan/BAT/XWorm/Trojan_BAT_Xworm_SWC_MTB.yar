
rule Trojan_BAT_Xworm_SWC_MTB{
	meta:
		description = "Trojan:BAT/Xworm.SWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 0e 00 00 01 13 07 09 28 ?? 00 00 0a 16 11 07 16 1a 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 16 11 07 1a 1a 28 ?? 00 00 0a 11 05 28 ?? 00 00 0a 16 11 07 1e 1a 28 ?? 00 00 0a 11 06 28 ?? 00 00 0a 16 11 07 1f 0c 1a 28 ?? 00 00 0a 11 07 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}