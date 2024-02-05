
rule Trojan_BAT_AsyncRAT_AT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 e8 03 00 00 28 90 01 03 0a 00 00 07 17 58 0b 07 73 90 01 03 0a 17 19 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}