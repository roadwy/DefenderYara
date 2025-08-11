
rule Trojan_BAT_XWorm_BAC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 11 04 6f 4e 01 00 0a 04 11 04 6f 4e 01 00 0a fe 01 16 fe 01 13 05 11 05 2c 02 2b 1a 08 03 11 04 6f 4e 01 00 0a 6f af 02 00 0a 26 11 04 17 d6 13 04 11 04 09 31 c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}