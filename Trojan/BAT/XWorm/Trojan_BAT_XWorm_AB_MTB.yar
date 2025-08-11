
rule Trojan_BAT_XWorm_AB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 80 06 00 00 04 2b 11 7e 07 00 00 04 7e 06 00 00 04 16 91 6f 5f 00 00 0a 38 ab 00 00 00 7e 07 00 00 04 7e 06 00 00 04 16 06 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}