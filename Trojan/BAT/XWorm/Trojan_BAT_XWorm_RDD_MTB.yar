
rule Trojan_BAT_XWorm_RDD_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 1e 00 00 06 80 01 00 00 04 7e 01 00 00 04 28 03 00 00 06 28 1c 00 00 0a 28 1d 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}