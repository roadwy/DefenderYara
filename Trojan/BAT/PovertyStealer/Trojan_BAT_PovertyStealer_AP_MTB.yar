
rule Trojan_BAT_PovertyStealer_AP_MTB{
	meta:
		description = "Trojan:BAT/PovertyStealer.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 07 16 73 90 01 01 00 00 0a 13 04 11 04 08 6f 90 01 01 00 00 0a 73 90 01 01 00 00 06 08 6f 90 01 01 00 00 0a 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}