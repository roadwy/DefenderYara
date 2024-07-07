
rule Trojan_BAT_DCRat_RDK_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0f 01 00 06 28 12 01 00 06 74 22 00 00 01 0a 73 dd 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}