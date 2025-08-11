
rule Trojan_BAT_XWorm_AE_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 05 1f 0f 13 0a 1f 17 13 0d 1f 4e 13 13 20 15 01 00 00 13 16 20 1c 01 00 00 13 19 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}