
rule Trojan_BAT_AsyncRAT_NYN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 25 26 0b 20 90 01 03 00 28 90 01 03 06 25 26 0c 20 90 01 03 00 28 90 01 03 06 0d 20 90 01 03 00 28 90 01 03 06 20 90 01 03 00 28 90 01 03 06 20 90 01 03 00 28 90 01 03 06 25 26 28 90 01 03 0a 13 04 28 90 01 03 06 25 26 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {42 50 4f 49 69 4e 38 37 37 } //00 00  BPOIiN877
	condition:
		any of ($a_*)
 
}