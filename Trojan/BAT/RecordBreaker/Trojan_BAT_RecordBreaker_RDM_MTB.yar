
rule Trojan_BAT_RecordBreaker_RDM_MTB{
	meta:
		description = "Trojan:BAT/RecordBreaker.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 32 00 00 0a a2 25 18 18 8c 49 00 00 01 a2 25 19 17 8d 17 00 00 01 25 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}