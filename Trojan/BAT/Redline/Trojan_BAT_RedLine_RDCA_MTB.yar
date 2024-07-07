
rule Trojan_BAT_RedLine_RDCA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 6f 4c 00 00 0a 03 07 03 6f 6d 00 00 0a 5d 6f 4c 00 00 0a 61 0c 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}