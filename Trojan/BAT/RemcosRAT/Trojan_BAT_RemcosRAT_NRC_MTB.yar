
rule Trojan_BAT_RemcosRAT_NRC_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 e5 00 00 0a 80 90 01 03 04 11 04 20 90 01 03 76 5a 20 90 01 03 a0 61 38 90 01 03 ff 00 11 04 20 90 01 03 6f 5a 20 90 01 03 9e 61 38 90 01 03 ff 11 04 20 90 01 03 88 5a 20 90 01 03 4d 61 90 00 } //01 00 
		$a_01_1 = {52 61 6e 64 6f 6d 4d 61 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  RandomMaker.Properties.Resources
	condition:
		any of ($a_*)
 
}