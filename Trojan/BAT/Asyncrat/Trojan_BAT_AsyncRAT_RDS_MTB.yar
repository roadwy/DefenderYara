
rule Trojan_BAT_AsyncRAT_RDS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 04 6f 1c 00 00 0a 5d 28 90 01 04 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}