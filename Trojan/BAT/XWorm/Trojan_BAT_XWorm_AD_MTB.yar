
rule Trojan_BAT_XWorm_AD_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 91 61 06 09 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 06 8e 69 5d 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}