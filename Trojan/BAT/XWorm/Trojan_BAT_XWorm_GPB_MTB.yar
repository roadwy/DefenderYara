
rule Trojan_BAT_XWorm_GPB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 17 61 d1 0c 07 08 6f 90 01 01 00 00 0a 26 09 17 58 0d 09 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}