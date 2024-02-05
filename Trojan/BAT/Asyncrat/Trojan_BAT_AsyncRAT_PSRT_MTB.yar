
rule Trojan_BAT_AsyncRAT_PSRT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 00 09 28 90 01 01 00 00 0a 07 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 09 72 0b 00 00 70 6f 90 01 01 00 00 0a 26 09 08 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}