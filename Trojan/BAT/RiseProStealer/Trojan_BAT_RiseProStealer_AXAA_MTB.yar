
rule Trojan_BAT_RiseProStealer_AXAA_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.AXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 09 16 09 8e 69 28 90 01 01 00 00 06 13 06 90 00 } //2
		$a_03_1 = {06 13 09 17 28 90 01 01 00 00 06 3a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}