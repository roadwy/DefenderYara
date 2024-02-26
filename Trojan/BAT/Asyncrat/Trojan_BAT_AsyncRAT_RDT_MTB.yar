
rule Trojan_BAT_AsyncRAT_RDT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 0e 00 00 04 7e 0a 00 00 04 6f 84 00 00 06 28 17 00 00 0a 73 19 00 00 0a 80 0c 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}