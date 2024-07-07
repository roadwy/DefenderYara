
rule Backdoor_BAT_Bladabindi_MMC_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {1f 0b 11 0b a2 28 90 01 0e 13 0c 2b 06 0b 38 90 01 04 11 0c 20 90 01 0e 13 0d 2b 06 0a 38 90 01 04 11 0d 20 90 01 0e 13 0e 73 90 01 09 11 0e 6f 90 01 04 14 17 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}