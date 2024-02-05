
rule Trojan_BAT_AsyncRAT_NZQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 0c 13 00 61 fe 0e 1a 00 fe 0c 16 00 1f 0f 64 fe 0c 16 00 1f 11 62 60 fe 0e 16 00 fe 0c 12 00 fe 0c 12 00 1b 64 61 fe 0e 12 00 } //01 00 
		$a_01_1 = {38 66 31 31 2d 63 35 64 34 33 30 36 31 61 31 30 30 } //00 00 
	condition:
		any of ($a_*)
 
}