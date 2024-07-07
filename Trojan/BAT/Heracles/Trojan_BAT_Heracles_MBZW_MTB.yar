
rule Trojan_BAT_Heracles_MBZW_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 7b 0a 00 00 95 5f 11 28 20 4e 03 00 00 95 61 58 13 37 38 03 0f 00 00 11 37 11 28 20 10 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}