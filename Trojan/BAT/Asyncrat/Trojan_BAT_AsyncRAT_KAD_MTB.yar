
rule Trojan_BAT_AsyncRAT_KAD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 06 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 07 11 07 11 05 16 11 05 8e 69 6f 90 01 01 00 00 0a 11 07 6f 90 01 01 00 00 0a dd 90 01 01 00 00 00 11 07 39 90 01 01 00 00 00 11 07 6f 90 01 01 00 00 0a dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}