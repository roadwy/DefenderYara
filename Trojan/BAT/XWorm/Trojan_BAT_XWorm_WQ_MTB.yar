
rule Trojan_BAT_XWorm_WQ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 f6 08 00 70 11 05 6f 1c 00 00 0a 28 1d 00 00 0a 28 17 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}