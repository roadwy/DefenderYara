
rule Trojan_BAT_AsyncRAT_SPT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 07 08 91 20 90 01 03 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}