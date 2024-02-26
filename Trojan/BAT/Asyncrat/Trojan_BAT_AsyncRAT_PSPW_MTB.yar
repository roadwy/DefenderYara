
rule Trojan_BAT_AsyncRAT_PSPW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 5f 00 00 0a 73 90 01 03 0a 7d 0b 00 00 04 02 6f 90 01 03 06 72 90 01 03 70 28 90 01 03 06 6f 90 01 03 0a 02 7b 0b 00 00 04 6f 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 02 20 e8 03 00 00 28 90 01 03 0a 7d 0e 00 00 04 02 28 16 00 00 06 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}