
rule Trojan_BAT_AsyncRAT_LN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.LN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 02 11 05 91 07 61 08 09 91 61 b4 9c 09 03 90 01 05 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 06 31 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}