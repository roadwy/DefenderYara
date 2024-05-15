
rule Trojan_BAT_AsyncRAT_AW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 11 07 72 90 01 02 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 2b 6f 90 01 01 00 00 0a 26 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}