
rule Trojan_BAT_DCRat_RDO_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 94 13 0c 11 05 11 0a 02 11 0a 91 11 0c 61 28 ?? ?? ?? ?? 9c 11 0a 17 58 13 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}