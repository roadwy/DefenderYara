
rule Trojan_BAT_RecordBreaker_RDH_MTB{
	meta:
		description = "Trojan:BAT/RecordBreaker.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {e0 4a 61 54 fe 0c 01 00 fe 0c 00 00 20 02 00 00 00 59 20 00 00 00 00 9c fe 0c 00 00 20 01 00 00 00 59 fe 0e 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}