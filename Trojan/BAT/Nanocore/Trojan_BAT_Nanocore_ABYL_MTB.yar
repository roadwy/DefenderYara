
rule Trojan_BAT_Nanocore_ABYL_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 2b 2b 30 1b 2c f9 1e 2c f6 2b 2b 2b 30 2b 31 2b 36 75 90 01 01 00 00 1b 2b 36 19 2c 0f 16 2d e1 2b 31 16 2b 31 8e 69 28 90 01 01 00 00 0a 07 2a 28 90 01 01 00 00 06 2b ce 0a 2b cd 28 90 01 01 00 00 0a 2b ce 06 2b cd 6f 90 01 01 00 00 0a 2b c8 28 90 01 01 00 00 06 2b c3 0b 2b c7 07 2b cc 07 2b cc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}