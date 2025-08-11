
rule Trojan_BAT_XWorm_AC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 04 08 0e 04 0e 04 8e 69 12 05 11 07 11 07 8e 69 11 04 11 04 8e 69 12 08 16 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}