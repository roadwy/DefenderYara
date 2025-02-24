
rule Trojan_BAT_Stealc_EAOO_MTB{
	meta:
		description = "Trojan:BAT/Stealc.EAOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 09 11 10 9a 6f 68 00 00 0a 6f 6d 00 00 0a 13 11 11 11 2c 07 17 0a 38 85 02 00 00 00 11 10 17 d6 13 10 11 10 11 0f 31 d6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}