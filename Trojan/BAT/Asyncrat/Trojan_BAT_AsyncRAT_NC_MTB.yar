
rule Trojan_BAT_AsyncRAT_NC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 06 51 00 00 06 73 90 01 02 00 0a 0c 72 90 01 02 00 70 28 90 01 02 00 0a 0d 06 08 09 6f 90 01 02 00 0a 7d 90 01 02 00 04 90 00 } //01 00 
		$a_01_1 = {54 69 66 66 79 2e 54 64 39 6e 79 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {45 63 6f 6e 6f 63 37 69 63 73 } //00 00 
	condition:
		any of ($a_*)
 
}