
rule Trojan_BAT_XWorm_AF_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7e 01 01 00 04 20 42 01 00 00 7e 01 01 00 04 20 42 01 00 00 91 7e 01 01 00 04 20 8c 01 00 00 91 61 20 ff 00 00 00 5f 9c 58 5a 0c 02 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}