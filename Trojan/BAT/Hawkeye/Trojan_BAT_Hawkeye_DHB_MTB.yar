
rule Trojan_BAT_Hawkeye_DHB_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {06 08 09 1b 5b 93 6f 90 01 04 1f 0a 62 13 04 09 1b 5b 17 58 08 8e 69 fe 04 13 05 11 05 2c 14 11 04 06 08 09 1b 5b 17 58 93 6f 90 01 04 1b 62 60 13 04 09 1b 5b 18 58 90 00 } //1
		$a_02_1 = {08 8e 69 fe 04 13 06 11 06 2c 12 11 04 06 08 09 1b 5b 18 58 93 6f 90 01 04 60 13 04 20 ff 00 00 00 11 04 1f 0f 09 1b 5d 59 1e 59 1f 1f 5f 63 5f 13 04 07 11 04 d2 6f 90 01 04 00 00 09 1e 58 0d 09 02 6f 90 01 04 1b 5a fe 04 13 07 11 07 3a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}