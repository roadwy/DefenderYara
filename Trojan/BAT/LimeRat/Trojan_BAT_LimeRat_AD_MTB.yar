
rule Trojan_BAT_LimeRat_AD_MTB{
	meta:
		description = "Trojan:BAT/LimeRat.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {05 0e 04 7e 0c 00 00 04 20 24 02 00 00 7e 0c 00 00 04 20 24 02 00 00 91 05 5a 20 de 00 00 00 5f 9c 61 1f 6c 59 06 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}