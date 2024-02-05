
rule Trojan_BAT_AsyncRAT_MBID_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 01 00 00 0a 04 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 07 6f 90 01 01 00 00 0a 00 73 90 01 01 00 00 0a 0d 09 08 6f 55 00 00 0a 00 09 05 6f 90 01 01 00 00 0a 00 09 0e 04 6f 90 01 01 00 00 0a 00 09 90 00 } //01 00 
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}