
rule Trojan_BAT_RiseProStealer_CPAA_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.CPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 11 04 28 90 01 02 00 06 00 25 17 28 90 01 02 00 06 00 25 18 28 90 01 02 00 06 00 25 07 28 90 01 02 00 06 00 13 08 90 00 } //2
		$a_03_1 = {06 13 09 11 09 09 16 09 8e 69 28 90 01 02 00 06 13 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}