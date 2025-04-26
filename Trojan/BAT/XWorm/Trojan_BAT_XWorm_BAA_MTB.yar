
rule Trojan_BAT_XWorm_BAA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {9c 08 11 04 d6 0c 11 04 1f 1f 63 08 61 11 04 1f 1f 63 09 61 31 9e } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}