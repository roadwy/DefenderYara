
rule Trojan_BAT_AsyncRAT_PTGG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PTGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 ba 02 00 70 28 90 01 01 00 00 0a 72 be 02 00 70 72 c2 02 00 70 6f 7c 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 a2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}