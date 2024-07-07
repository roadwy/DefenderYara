
rule Trojan_BAT_Scarsi_AAEW_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.AAEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 8e 69 17 da 13 0b 16 13 0c 2b 1b 11 04 11 0c 09 11 0c 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 0c 17 d6 13 0c 11 0c 11 0b 31 df 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}