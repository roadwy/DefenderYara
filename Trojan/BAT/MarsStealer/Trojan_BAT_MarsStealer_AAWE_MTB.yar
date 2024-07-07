
rule Trojan_BAT_MarsStealer_AAWE_MTB{
	meta:
		description = "Trojan:BAT/MarsStealer.AAWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 21 45 00 70 28 90 01 01 00 00 0a 00 72 39 45 00 70 28 90 01 01 00 00 0a 61 69 90 00 } //2
		$a_03_1 = {72 55 45 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 5b 59 7e 90 01 01 00 00 0a 8e 59 7e 90 01 01 00 00 0a 8e 59 28 90 01 01 00 00 06 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}