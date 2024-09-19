
rule Trojan_BAT_RedLine_RDFF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 61 00 00 70 28 44 00 00 0a 72 93 00 00 70 28 44 00 00 0a 6f 45 00 00 0a 0c 73 46 00 00 0a 0d 09 08 17 73 47 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}