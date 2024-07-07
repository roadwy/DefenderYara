
rule Trojan_BAT_Stealer_SPCC_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SPCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 16 30 06 73 90 01 03 0a 7a 02 7b 90 01 03 04 6f 90 01 03 0a 03 16 03 8e 69 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}