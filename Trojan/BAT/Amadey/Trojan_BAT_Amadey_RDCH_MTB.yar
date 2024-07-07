
rule Trojan_BAT_Amadey_RDCH_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 6f 8e 00 00 0a 28 8f 00 00 0a 0c 08 73 90 00 00 0a 07 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}