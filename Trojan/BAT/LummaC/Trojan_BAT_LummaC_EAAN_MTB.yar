
rule Trojan_BAT_LummaC_EAAN_MTB{
	meta:
		description = "Trojan:BAT/LummaC.EAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58 13 2f 11 2f 20 00 01 00 00 32 c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}