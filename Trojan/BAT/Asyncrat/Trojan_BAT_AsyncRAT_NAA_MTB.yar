
rule Trojan_BAT_AsyncRAT_NAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 88 48 f6 ff 20 90 01 03 ff 59 6f 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 13 06 12 06 1b 8d 90 01 03 01 25 16 20 90 01 03 00 8c 90 01 03 01 a2 25 17 72 90 01 03 70 a2 25 18 72 90 01 03 70 a2 25 19 20 90 01 03 00 8c 90 01 03 01 a2 25 1a 1f 5d 8c 90 01 03 01 a2 28 90 01 03 06 00 11 06 6f 90 01 03 0a 6f 90 01 03 0a 20 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {76 74 6b 6e 74 73 79 62 75 6d 6d 67 62 75 65 6b 2e 52 65 73 6f 75 72 63 65 73 } //00 00  vtkntsybummgbuek.Resources
	condition:
		any of ($a_*)
 
}