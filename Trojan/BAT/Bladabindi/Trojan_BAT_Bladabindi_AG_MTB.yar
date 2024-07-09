
rule Trojan_BAT_Bladabindi_AG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {11 05 02 11 05 91 [0-10] 91 61 b4 9c [0-10] 00 00 04 6f [0-10] 0a 17 da fe 01 13 07 11 07 2c 04 16 [0-15] 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c1 } //1
		$a_00_1 = {08 11 05 02 11 05 91 07 61 06 09 91 61 b4 9c 09 7e 72 01 00 04 6f 6a 00 00 0a 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 04 31 ce } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}