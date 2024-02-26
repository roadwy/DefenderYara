
rule Trojan_BAT_AsyncRAT_PTGH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PTGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 28 90 01 01 00 00 0a fe 0c 02 00 6f ac 01 00 06 6f 30 00 00 0a 7d 35 01 00 04 fe 0c 03 00 fe 0c 02 00 6f a8 01 00 06 72 cb 00 00 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}