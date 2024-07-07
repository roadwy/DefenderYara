
rule Trojan_BAT_XWorm_CCHT_MTB{
	meta:
		description = "Trojan:BAT/XWorm.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 7e 45 00 00 04 28 90 01 01 00 00 06 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 06 18 6f 90 01 01 01 00 0a 06 6f 90 01 01 01 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 90 01 01 01 00 0a 0b de 11 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}