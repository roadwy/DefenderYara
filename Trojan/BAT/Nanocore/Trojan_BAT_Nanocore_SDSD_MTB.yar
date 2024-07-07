
rule Trojan_BAT_Nanocore_SDSD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.SDSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0b 06 07 16 1a 6f 90 01 03 0a 26 07 16 28 90 01 03 0a 0c 06 16 73 90 01 03 0a 0d 08 8d 90 01 03 01 13 04 09 11 04 16 08 6f 90 01 03 0a 26 11 90 00 } //1
		$a_02_1 = {0a 0a 06 02 28 90 01 03 06 28 90 01 03 06 28 90 01 03 0a 06 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}