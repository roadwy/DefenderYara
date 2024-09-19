
rule Trojan_BAT_XWorm_RDJ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 6f 35 01 00 0a 13 07 73 36 01 00 0a 13 04 11 04 11 07 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}