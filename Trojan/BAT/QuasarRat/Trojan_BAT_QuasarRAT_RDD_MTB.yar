
rule Trojan_BAT_QuasarRAT_RDD_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 12 00 28 47 01 00 0a 12 00 28 48 01 00 0a 20 20 00 cc 00 28 12 00 00 06 26 11 04 } //00 00 
	condition:
		any of ($a_*)
 
}