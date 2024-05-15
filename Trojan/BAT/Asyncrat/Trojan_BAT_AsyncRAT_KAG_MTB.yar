
rule Trojan_BAT_AsyncRAT_KAG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 91 61 04 08 20 90 01 01 10 00 00 58 20 90 01 01 10 00 00 59 04 8e 69 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}